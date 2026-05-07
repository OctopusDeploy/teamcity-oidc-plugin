package com.octopus.teamcity.oidc;

import com.nimbusds.jwt.SignedJWT;
import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.*;
import jetbrains.buildServer.users.SUser;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.File;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class JwtBuildStartContextTest {

    private static final String DEFAULT_HTTPS_ROOT = "https://localhost:8111";

    @Mock ExtensionHolder extensionHolder;
    @Mock SRunningBuild runningBuild;
    @Mock BuildStartContext buildStartContext;
    @Mock SBuildFeatureDescriptor jwtBuildFeatureBuildFeatureDescriptor;
    @Mock ServerPaths serverPaths;

    @TempDir File tempDir;

    private SBuildServer buildServerWithRootUrl(final String url) {
        final var server = mock(SBuildServer.class);
        lenient().when(server.getRootUrl()).thenReturn(url);
        return server;
    }

    private OidcIssuerUrlProvider providerFor(final String issuerUrl) {
        return new OidcIssuerUrlProvider(buildServerWithRootUrl(issuerUrl), new OidcSettingsManager(tempDir));
    }

    /** Creates a JwtBuildStartContext using the given issuer URL. */
    private JwtBuildStartContext newContext(final String issuerUrl) {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        return new JwtBuildStartContext(extensionHolder, providerFor(issuerUrl), keyManager);
    }

    /** Creates a JwtBuildStartContext using the standard HTTPS root URL. */
    private JwtBuildStartContext newContext() {
        return newContext(DEFAULT_HTTPS_ROOT);
    }

    /** Wires the JWT build feature into the build start context with the given parameters. */
    private void enableBuildFeature(final Map<String, String> params) {
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(List.of(jwtBuildFeatureBuildFeatureDescriptor));
        when(jwtBuildFeatureBuildFeatureDescriptor.getParameters()).thenReturn(params);
    }

    /** Mocks a TriggeredBy and wires it into the running build. Mockito defaults apply
     *  to methods like getUser() (null), isTriggeredBySnapshotDependency() (false), and
     *  getParameters() (empty map). */
    private TriggeredBy stubTrigger() {
        final var triggeredBy = mock(TriggeredBy.class);
        when(runningBuild.getTriggeredBy()).thenReturn(triggeredBy);
        return triggeredBy;
    }

    /** Mocks a TriggeredBy that reports a non-null user (i.e. user-initiated build). */
    private void stubUserTrigger() {
        when(stubTrigger().getUser()).thenReturn(mock(SUser.class));
    }

    /** Stubs the build's branch info so the JWT carries that branch name. */
    private void stubBranch(final String branchName) {
        final var branch = mock(Branch.class);
        when(branch.getName()).thenReturn(branchName);
        when(runningBuild.getBranch()).thenReturn(branch);
    }

    /** Runs the context and returns the parsed JWT, asserting exactly one token was issued. */
    private SignedJWT runAndParseToken(final JwtBuildStartContext context) throws Exception {
        final var captor = ArgumentCaptor.forClass(String.class);
        context.updateParameters(buildStartContext);
        verify(buildStartContext).addSharedParameter(eq("jwt.token"), captor.capture());
        return SignedJWT.parse(captor.getValue());
    }

    private static long ttlSecondsOf(final SignedJWT jwt) throws Exception {
        return (jwt.getJWTClaimsSet().getExpirationTime().getTime()
                - jwt.getJWTClaimsSet().getIssueTime().getTime()) / 1000;
    }

    @Test
    public void testRegister() {
        newContext("https://tc.example.com").register();
        verify(extensionHolder, times(1)).registerExtension(any(), any(), any());
    }

    @Test
    public void doNotUpdateParametersWhenBuildFeatureDisabled() {
        when(buildStartContext.getBuild()).thenReturn(runningBuild);
        when(runningBuild.getBuildFeaturesOfType("oidc-plugin")).thenReturn(Collections.emptyList());

        newContext("https://tc.example.com").updateParameters(buildStartContext);

        verify(buildStartContext, never()).addSharedParameter(any(), any());
    }

    @Test
    public void doesNotThrowWhenBuildIsTriggeredAutomaticallyWithNoUser() {
        enableBuildFeature(Map.of());
        final var trigger = stubTrigger();
        when(trigger.getParameters()).thenReturn(Map.of("type", "schedulingTrigger"));

        final var context = newContext();
        AssertionsForClassTypes.assertThatNoException()
                .isThrownBy(() -> context.updateParameters(buildStartContext));
        verify(buildStartContext, times(1)).addSharedParameter(eq("jwt.token"), any());
    }

    @Test
    public void branchClaimIsTheBranchNameNotAnObjectReference() throws Exception {
        enableBuildFeature(Map.of());
        stubBranch("refs/heads/main");
        stubUserTrigger();

        final var jwt = runAndParseToken(newContext());

        assertThat(jwt.getJWTClaimsSet().getStringClaim("branch")).isEqualTo("refs/heads/main");
    }

    @Test
    public void branchClaimIsOmittedWhenBuildHasNoBranch() throws Exception {
        // Build types with no VCS root attached have no branch info; emitting branch=""
        // would be misleading to OIDC consumers, so the claim is omitted entirely.
        enableBuildFeature(Map.of());
        stubUserTrigger();
        // runningBuild.getBranch() returns null by default (no stub)

        final var claims = runAndParseToken(newContext()).getJWTClaimsSet();

        assertThat(claims.getClaim("branch")).isNull();
    }

    @Test
    public void tokenTtlIsReadFromBuildFeatureParameters() throws Exception {
        enableBuildFeature(Map.of("ttl_minutes", "5"));
        stubUserTrigger();

        assertThat(ttlSecondsOf(runAndParseToken(newContext()))).isEqualTo(5 * 60);
    }

    @Test
    public void tokenTtlDefaultsTo10MinutesWhenNotConfigured() throws Exception {
        enableBuildFeature(Map.of());
        stubUserTrigger();

        assertThat(ttlSecondsOf(runAndParseToken(newContext()))).isEqualTo(10 * 60);
    }

    @Test
    public void tokenTtlIsClamppedToOneDayMaximum() throws Exception {
        enableBuildFeature(Map.of("ttl_minutes", "999999"));
        stubUserTrigger();

        assertThat(ttlSecondsOf(runAndParseToken(newContext()))).isEqualTo(1440 * 60);
    }

    @Test
    public void tokenTtlDefaultsTo10MinutesWhenTtlParamIsNotNumeric() throws Exception {
        enableBuildFeature(Map.of("ttl_minutes", "not-a-number"));
        stubUserTrigger();

        assertThat(ttlSecondsOf(runAndParseToken(newContext()))).isEqualTo(10 * 60);
    }

    @Test
    public void doesNotInjectTokenWhenRootUrlIsNotHttps() {
        enableBuildFeature(Map.of());
        final var context = newContext("http://localhost:8111");

        AssertionsForClassTypes.assertThatNoException()
                .isThrownBy(() -> context.updateParameters(buildStartContext));
        verify(buildStartContext, never()).addSharedParameter(any(), any());
    }

    @Test
    public void updateParametersWhenBuildFeatureEnabled() {
        enableBuildFeature(Map.of());
        stubUserTrigger();

        newContext().updateParameters(buildStartContext);

        verify(buildStartContext, times(1)).addSharedParameter(eq("jwt.token"), any());
    }

    @Test
    public void audienceIsConfigurablePerBuildFeature() throws Exception {
        enableBuildFeature(Map.of("audience", "my-cloud-audience"));
        stubTrigger();

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getAudience())
                .containsExactly("my-cloud-audience");
    }

    @Test
    public void audienceDefaultsToServerRootUrlWhenNotConfigured() throws Exception {
        enableBuildFeature(Map.of());
        stubTrigger();

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getAudience())
                .containsExactly(DEFAULT_HTTPS_ROOT);
    }

    @Test
    public void audienceDefaultsToServerRootUrlWhenAudienceParamIsBlank() throws Exception {
        enableBuildFeature(Map.of("audience", ""));
        stubTrigger();

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getAudience())
                .containsExactly(DEFAULT_HTTPS_ROOT);
    }

    @Test
    public void triggerTypeClaimIsUserWhenUserIsAvailable() throws Exception {
        enableBuildFeature(Map.of());
        stubUserTrigger();

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getStringClaim("trigger_type"))
                .isEqualTo("user");
    }

    @Test
    public void triggerTypeClaimIsSnapshotDependencyEvenIfUserPresent() throws Exception {
        enableBuildFeature(Map.of());
        final var trigger = stubTrigger();
        when(trigger.isTriggeredBySnapshotDependency()).thenReturn(true);
        // User propagates from upstream user-triggered build, but the dep itself is a snapshot dep
        lenient().when(trigger.getUser()).thenReturn(mock(SUser.class));

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getStringClaim("trigger_type"))
                .isEqualTo("snapshotDependency");
    }

    @Test
    public void triggerTypeClaimFallsBackToParametersTypeWhenNoUser() throws Exception {
        enableBuildFeature(Map.of());
        final var trigger = stubTrigger();
        when(trigger.getParameters()).thenReturn(Map.of("type", "vcsTrigger"));

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getStringClaim("trigger_type"))
                .isEqualTo("vcsTrigger");
    }

    @Test
    public void triggerTypeClaimDefaultsToUnknownWhenNoSourceAvailable() throws Exception {
        enableBuildFeature(Map.of());
        stubTrigger();

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getStringClaim("trigger_type"))
                .isEqualTo("unknown");
    }

    @Test
    public void mandatoryClaimsAlwaysIncludedRegardlessOfClaimsConfig() throws Exception {
        enableBuildFeature(Map.of("claims", ""));
        when(runningBuild.getBuildTypeExternalId()).thenReturn("BuildType_1");
        when(runningBuild.getProjectExternalId()).thenReturn("Project_1");
        stubTrigger();

        final var claims = runAndParseToken(newContext()).getJWTClaimsSet();

        assertThat(claims.getStringClaim("build_type_external_id")).isEqualTo("BuildType_1");
        assertThat(claims.getStringClaim("project_external_id")).isEqualTo("Project_1");
    }

    @Test
    public void onlyConfiguredOptionalClaimsAreIncluded() throws Exception {
        enableBuildFeature(Map.of("claims", "branch"));
        stubBranch("refs/heads/main");

        final var claims = runAndParseToken(newContext()).getJWTClaimsSet();

        assertThat(claims.getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(claims.getClaim("trigger_type")).isNull();
    }

    @Test
    public void claimsWithWhitespaceAroundCommasAreAllIncluded() throws Exception {
        enableBuildFeature(Map.of("claims", "branch, trigger_type"));
        stubBranch("refs/heads/main");
        stubUserTrigger();

        final var claims = runAndParseToken(newContext()).getJWTClaimsSet();

        assertThat(claims.getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(claims.getStringClaim("trigger_type")).isEqualTo("user");
    }

    @Test
    public void allClaimsIncludedWhenClaimsParamAbsent() throws Exception {
        enableBuildFeature(Map.of());
        when(runningBuild.getBuildTypeExternalId()).thenReturn("BuildType_1");
        when(runningBuild.getProjectExternalId()).thenReturn("Project_1");
        stubBranch("refs/heads/main");
        stubUserTrigger();

        assertThat(runAndParseToken(newContext()).getJWTClaimsSet().getClaims())
                .containsKeys("branch", "build_type_external_id", "project_external_id", "trigger_type");
    }

    @Test
    public void unknownClaimNamesAreIgnoredAndDoNotAppearInToken() throws Exception {
        enableBuildFeature(Map.of("claims", "branch,injected_claim,__proto__"));
        stubBranch("refs/heads/main");

        final var claims = runAndParseToken(newContext()).getJWTClaimsSet();

        assertThat(claims.getStringClaim("branch")).isEqualTo("refs/heads/main");
        assertThat(claims.getClaim("injected_claim")).isNull();
        assertThat(claims.getClaim("__proto__")).isNull();
    }

    @Test
    public void issuerClaimHasTrailingSlashStripped() throws Exception {
        enableBuildFeature(Map.of());
        stubTrigger();

        assertThat(runAndParseToken(newContext("https://localhost:8111/")).getJWTClaimsSet().getIssuer())
                .isEqualTo("https://localhost:8111");
    }

    @Test
    public void jtiClaimIsUniquePerToken() throws Exception {
        enableBuildFeature(Map.of());
        when(runningBuild.getBuildId()).thenReturn(42L);
        stubTrigger();
        final var context = newContext();

        final var captor = ArgumentCaptor.forClass(String.class);
        context.updateParameters(buildStartContext);
        context.updateParameters(buildStartContext);
        verify(buildStartContext, times(2)).addSharedParameter(eq("jwt.token"), captor.capture());

        final var jti1 = SignedJWT.parse(captor.getAllValues().get(0)).getJWTClaimsSet().getJWTID();
        final var jti2 = SignedJWT.parse(captor.getAllValues().get(1)).getJWTClaimsSet().getJWTID();
        assertThat(jti1).startsWith("42-").isNotEqualTo(jti2);
        assertThat(jti2).startsWith("42-");
    }
}
