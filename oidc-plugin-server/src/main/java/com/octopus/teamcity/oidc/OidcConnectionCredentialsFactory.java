package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.ProjectManager;
import jetbrains.buildServer.serverSide.SBuildType;
import jetbrains.buildServer.serverSide.SProject;
import jetbrains.buildServer.serverSide.auth.AuthorityHolder;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.serverSide.auth.SecurityContext;
import jetbrains.buildServer.serverSide.connections.ConnectionDescriptor;
import jetbrains.buildServer.serverSide.connections.credentials.ConnectionCredentials;
import jetbrains.buildServer.serverSide.connections.credentials.ConnectionCredentialsException;
import jetbrains.buildServer.serverSide.connections.credentials.ConnectionCredentialsFactory;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Issues an OIDC token outside a build, to another plugin acting for the signed-in user — for
 * example to list a relying party's resources while a form is being edited. Reached through
 * TeamCity's {@code ProjectConnectionCredentialsManager.requestConnectionCredentials}, so callers
 * need no dependency on this plugin.
 *
 * <p>The token carries the subject a build of the requested build configuration gets, so it is as
 * powerful as that build's token. Callers must use it on the server only: never send it to a
 * browser, log it, or persist it.
 */
public class OidcConnectionCredentialsFactory implements ConnectionCredentialsFactory {
    /** External id of the build configuration the token is for; absent for a project-scoped token. */
    public static final String BUILD_TYPE_ID_PARAM = "oidc.edit.buildTypeId";
    public static final String ID_TOKEN = "id_token";
    public static final String SUBJECT = "subject";
    /** Expiry in epoch seconds. */
    public static final String EXPIRES_AT = "expires_at";

    static final int TTL_MINUTES = 1;
    /** TeamCity's own pages identify a build configuration as {@code buildType:<externalId>}. */
    private static final String BUILD_TYPE_PREFIX = "buildType:";
    /** A person, not a trigger, is the actor, as for a manually run build. */
    private static final String TRIGGER_TYPE = "user";
    private static final Logger LOG = Logger.getLogger(OidcConnectionCredentialsFactory.class.getName());

    private final ExtensionHolder extensionHolder;
    private final OidcConnectionsManager connectionsManager;
    private final JwtKeyManager keyManager;
    private final OidcIssuerUrlProvider issuerUrlProvider;
    private final ProjectManager projectManager;
    private final SecurityContext securityContext;

    public OidcConnectionCredentialsFactory(@NotNull final ExtensionHolder extensionHolder,
                                            @NotNull final OidcConnectionsManager connectionsManager,
                                            @NotNull final JwtKeyManager keyManager,
                                            @NotNull final OidcIssuerUrlProvider issuerUrlProvider,
                                            @NotNull final ProjectManager projectManager,
                                            @NotNull final SecurityContext securityContext) {
        this.extensionHolder = extensionHolder;
        this.connectionsManager = connectionsManager;
        this.keyManager = keyManager;
        this.issuerUrlProvider = issuerUrlProvider;
        this.projectManager = projectManager;
        this.securityContext = securityContext;
    }

    public void register() {
        extensionHolder.registerExtension(ConnectionCredentialsFactory.class, getClass().getName(), this);
        LOG.info("JWT plugin: OidcConnectionCredentialsFactory registered as ConnectionCredentialsFactory");
    }

    @Override
    public @NotNull String getType() {
        return OidcConnectionProvider.TYPE;
    }

    @Override
    @Deprecated
    public @NotNull ConnectionCredentials requestCredentials(@NotNull final ConnectionDescriptor connectionDescriptor)
            throws ConnectionCredentialsException {
        throw new ConnectionCredentialsException("An OIDC token can only be requested for a project.");
    }

    @Override
    public @NotNull ConnectionCredentials requestCredentials(@NotNull final SProject project,
                                                            @NotNull final ConnectionDescriptor connectionDescriptor)
            throws ConnectionCredentialsException {
        try {
            return issue(project, connectionDescriptor);
        } catch (final ConnectionCredentialsException e) {
            LOG.warning("JWT plugin: refused an OIDC token for connection '" + sanitize(connectionDescriptor.getId())
                    + "' requested by " + callerName() + ": " + sanitize(e.getMessage()));
            throw e;
        }
    }

    private @NotNull ConnectionCredentials issue(@NotNull final SProject project,
                                                 @NotNull final ConnectionDescriptor connectionDescriptor)
            throws ConnectionCredentialsException {
        final AuthorityHolder caller = requireSignedInUser();
        // For a build configuration, findBuildType also checks Edit Project on its project.
        final Optional<SBuildType> buildType =
                findBuildType(caller, connectionDescriptor.getParameters().get(BUILD_TYPE_ID_PARAM));
        final SProject scope = buildType.map(SBuildType::getProject).orElse(project);
        if (buildType.isEmpty()) {
            requireEditProject(caller, scope);
        }
        final OidcConnection connection = resolveConnection(scope, connectionDescriptor);
        final var settings = connection.settings();
        if (buildType.isEmpty()) {
            requireConnectionDimension(settings);
        }
        final var issuerUrl = requireHttpsIssuerUrl();

        final var subject = SubjectComposer.compose(settings.subjectDimensions(), Optional.of(connection),
                scope.getProjectId(), buildType.map(SBuildType::getInternalId).orElse(null), "", TRIGGER_TYPE);
        final var issuedAt = Instant.now();
        final var expiry = issuedAt.plus(TTL_MINUTES, ChronoUnit.MINUTES);
        final var signed = sign(claims(subject, settings, issuerUrl, scope, buildType, issuedAt, expiry), settings);
        LOG.info("JWT plugin: issued an edit-time OIDC token to " + callerName()
                + " for connection '" + sanitize(connection.id()) + "' (sub=" + sanitize(subject)
                + ", aud=" + sanitize(settings.audience()) + ", kid=" + signed.getHeader().getKeyID() + ")");
        return new OidcCredentials(Map.of(
                ID_TOKEN, signed.serialize(),
                SUBJECT, subject,
                EXPIRES_AT, String.valueOf(expiry.getEpochSecond())));
    }

    private @NotNull AuthorityHolder requireSignedInUser() throws ConnectionCredentialsException {
        final AuthorityHolder caller = securityContext.getAuthorityHolder();
        if (caller.getAssociatedUser() == null) {
            throw new ConnectionCredentialsException("An OIDC token can only be issued to a signed-in user.");
        }
        return caller;
    }

    private static void requireEditProject(@NotNull final AuthorityHolder caller, @NotNull final SProject project)
            throws ConnectionCredentialsException {
        if (!canEditProject(caller, project.getProjectId())) {
            throw new ConnectionCredentialsException(
                    "You do not have permission to edit project '" + project.getExternalId() + "'.");
        }
    }

    /**
     * Re-resolved rather than read from the descriptor: TeamCity merges the caller's parameters over
     * the stored ones, so the descriptor's audience or dimensions could be the caller's.
     */
    private @NotNull OidcConnection resolveConnection(@NotNull final SProject scope,
                                                      @NotNull final ConnectionDescriptor connectionDescriptor)
            throws ConnectionCredentialsException {
        final var connectionId = connectionDescriptor.getId();
        final OidcConnection connection = connectionsManager.resolve(scope, connectionId)
                .orElseThrow(() -> new ConnectionCredentialsException("OIDC connection '" + connectionId
                        + "' is not available to project '" + scope.getExternalId() + "'."));
        // Feature ids are unique only within a project, so a nearer project can reuse the id.
        if (!connection.projectId().equals(connectionDescriptor.getProjectId())) {
            throw new ConnectionCredentialsException("OIDC connection '" + connectionId
                    + "' resolves to a different connection from project '" + scope.getExternalId() + "'.");
        }
        return connection;
    }

    private static void requireConnectionDimension(@NotNull final IssuanceSettings settings)
            throws ConnectionCredentialsException {
        if (!settings.subjectDimensions().contains("connection")) {
            throw new ConnectionCredentialsException(
                    "Enable the connection subject dimension on this OIDC connection to use it outside a build.");
        }
    }

    private @NotNull String requireHttpsIssuerUrl() throws ConnectionCredentialsException {
        final var issuerUrl = issuerUrlProvider.getIssuerUrl();
        if (!OidcUrlUtils.isHttpsUrl(issuerUrl)) {
            throw new ConnectionCredentialsException("The TeamCity issuer URL is not HTTPS, so OIDC tokens cannot be issued.");
        }
        return issuerUrl;
    }

    private static @NotNull JWTClaimsSet claims(@NotNull final String subject,
                                                @NotNull final IssuanceSettings settings,
                                                @NotNull final String issuerUrl,
                                                @NotNull final SProject scope,
                                                @NotNull final Optional<SBuildType> buildType,
                                                @NotNull final Instant issuedAt,
                                                @NotNull final Instant expiry) {
        final var claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .subject(subject)
                .audience(List.of(settings.audience()))
                .issuer(issuerUrl)
                .issueTime(Date.from(issuedAt))
                .notBeforeTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiry))
                .claim("project_external_id", scope.getExternalId())
                .claim("project_internal_id", scope.getProjectId())
                .claim("trigger_type", TRIGGER_TYPE);
        buildType.ifPresent(configuration -> claims
                .claim("build_type_external_id", configuration.getExternalId())
                .claim("build_type_internal_id", configuration.getInternalId()));
        return claims.build();
    }

    private @NotNull SignedJWT sign(@NotNull final JWTClaimsSet claims, @NotNull final IssuanceSettings settings)
            throws ConnectionCredentialsException {
        try {
            return keyManager.sign(claims, settings.signingAlgorithm());
        } catch (final JOSEException | RuntimeException e) {
            LOG.log(Level.SEVERE, "JWT plugin: signing an edit-time OIDC token failed", e);
            throw new ConnectionCredentialsException(
                    "Signing the OIDC token failed — check the TeamCity server log for details", e);
        }
    }

    /**
     * A missing build configuration and one the caller cannot edit get the same message, so the
     * request cannot be used to find out which build configurations or projects exist.
     */
    private Optional<SBuildType> findBuildType(@NotNull final AuthorityHolder caller, @Nullable final String rawId)
            throws ConnectionCredentialsException {
        if (rawId == null || rawId.isBlank()) return Optional.empty();
        final var trimmed = rawId.trim();
        final var externalId = trimmed.startsWith(BUILD_TYPE_PREFIX) ? trimmed.substring(BUILD_TYPE_PREFIX.length()) : trimmed;
        final var buildType = projectManager.findBuildTypeByExternalId(externalId);
        if (buildType != null && canEditProject(caller, buildType.getProject().getProjectId())) {
            return Optional.of(buildType);
        }
        final var template = buildType == null ? projectManager.findBuildTypeTemplateByExternalId(externalId) : null;
        if (template != null && canEditProject(caller, template.getProjectId())) {
            throw new ConnectionCredentialsException(
                    "'" + externalId + "' is a template; an OIDC token can only be issued for a build configuration.");
        }
        throw new ConnectionCredentialsException("Build configuration '" + externalId
                + "' was not found, or you do not have permission to edit its project.");
    }

    private static boolean canEditProject(final AuthorityHolder caller, final String projectId) {
        return caller.isPermissionGrantedForProject(projectId, Permission.EDIT_PROJECT);
    }

    private String callerName() {
        final var user = securityContext.getAuthorityHolder().getAssociatedUser();
        return user == null ? "an unauthenticated caller" : "user '" + sanitize(user.getUsername()) + "'";
    }

    private static String sanitize(final String value) {
        return value == null ? "" : value.replaceAll("[\\r\\n\\t]", "_");
    }

    private record OidcCredentials(@NotNull Map<String, String> properties) implements ConnectionCredentials {
        @Override
        public @NotNull Map<String, String> getProperties() {
            return properties;
        }

        @Override
        public @NotNull String getProviderType() {
            return OidcConnectionProvider.TYPE;
        }
    }
}
