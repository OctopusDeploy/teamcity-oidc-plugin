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
                    + "' requested by " + callerName() + ": " + e.getMessage());
            throw e;
        }
    }

    private @NotNull ConnectionCredentials issue(@NotNull final SProject project,
                                                 @NotNull final ConnectionDescriptor connectionDescriptor)
            throws ConnectionCredentialsException {
        final AuthorityHolder caller = securityContext.getAuthorityHolder();
        if (caller.getAssociatedUser() == null) {
            throw new ConnectionCredentialsException("An OIDC token can only be issued to a signed-in user.");
        }
        final Optional<SBuildType> buildType = findBuildType(connectionDescriptor.getParameters().get(BUILD_TYPE_ID_PARAM));
        final SProject scope = buildType.map(SBuildType::getProject).orElse(project);
        if (!caller.isPermissionGrantedForProject(scope.getProjectId(), Permission.EDIT_PROJECT)) {
            throw new ConnectionCredentialsException(
                    "You do not have permission to edit project '" + scope.getExternalId() + "'.");
        }
        // Re-resolved rather than read from the descriptor: TeamCity merges the caller's parameters
        // over the stored ones, so the descriptor's audience or dimensions could be the caller's.
        final OidcConnection connection = connectionsManager.resolve(scope, connectionDescriptor.getId())
                .orElseThrow(() -> new ConnectionCredentialsException("OIDC connection '" + connectionDescriptor.getId()
                        + "' is not available to project '" + scope.getExternalId() + "'."));
        // Feature ids are unique only within a project, so a nearer project can reuse the id.
        if (!connection.projectId().equals(connectionDescriptor.getProjectId())) {
            throw new ConnectionCredentialsException("OIDC connection '" + connectionDescriptor.getId()
                    + "' resolves to a different connection from project '" + scope.getExternalId() + "'.");
        }
        final var settings = connection.settings();
        if (buildType.isEmpty() && !settings.subjectDimensions().contains("connection")) {
            throw new ConnectionCredentialsException(
                    "Enable the connection subject dimension on this OIDC connection to use it outside a build.");
        }
        final var issuerUrl = issuerUrlProvider.getIssuerUrl();
        if (!OidcUrlUtils.isHttpsUrl(issuerUrl)) {
            throw new ConnectionCredentialsException("The TeamCity issuer URL is not HTTPS, so OIDC tokens cannot be issued.");
        }

        final var subject = SubjectComposer.compose(settings.subjectDimensions(), Optional.of(connection),
                scope.getProjectId(), buildType.map(SBuildType::getInternalId).orElse(null), "", TRIGGER_TYPE);
        final var now = Instant.now();
        final var expiry = now.plus(TTL_MINUTES, ChronoUnit.MINUTES);
        final var claims = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .subject(subject)
                .audience(List.of(settings.audience()))
                .issuer(issuerUrl)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(expiry))
                .claim("project_external_id", scope.getExternalId())
                .claim("project_internal_id", scope.getProjectId())
                .claim("trigger_type", TRIGGER_TYPE);
        buildType.ifPresent(bt -> claims
                .claim("build_type_external_id", bt.getExternalId())
                .claim("build_type_internal_id", bt.getInternalId()));

        final SignedJWT signed;
        try {
            signed = keyManager.sign(claims.build(), settings.signingAlgorithm());
        } catch (final JOSEException e) {
            LOG.log(Level.SEVERE, "JWT plugin: signing an edit-time OIDC token failed", e);
            throw new ConnectionCredentialsException(
                    "Signing the OIDC token failed — check the TeamCity server log for details", e);
        }
        LOG.info("JWT plugin: issued an edit-time OIDC token to " + callerName()
                + " for connection '" + sanitize(connection.id()) + "' (sub=" + sanitize(subject)
                + ", aud=" + sanitize(settings.audience()) + ", kid=" + signed.getHeader().getKeyID() + ")");
        return new OidcCredentials(Map.of(
                ID_TOKEN, signed.serialize(),
                SUBJECT, subject,
                EXPIRES_AT, String.valueOf(expiry.getEpochSecond())));
    }

    private Optional<SBuildType> findBuildType(@Nullable final String rawId) throws ConnectionCredentialsException {
        if (rawId == null || rawId.isBlank()) return Optional.empty();
        final var trimmed = rawId.trim();
        final var externalId = trimmed.startsWith(BUILD_TYPE_PREFIX) ? trimmed.substring(BUILD_TYPE_PREFIX.length()) : trimmed;
        final var buildType = projectManager.findBuildTypeByExternalId(externalId);
        if (buildType != null) return Optional.of(buildType);
        if (projectManager.findBuildTypeTemplateByExternalId(externalId) != null) {
            throw new ConnectionCredentialsException(
                    "'" + externalId + "' is a template; an OIDC token can only be issued for a build configuration.");
        }
        throw new ConnectionCredentialsException("Build configuration '" + externalId + "' was not found.");
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
