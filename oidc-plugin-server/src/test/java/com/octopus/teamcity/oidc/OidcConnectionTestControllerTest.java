package com.octopus.teamcity.oidc;

import jetbrains.buildServer.ExtensionHolder;
import jetbrains.buildServer.serverSide.ProjectManager;
import jetbrains.buildServer.serverSide.SBuildServer;
import jetbrains.buildServer.serverSide.SBuildType;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.serverSide.auth.Permission;
import jetbrains.buildServer.users.SUser;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class OidcConnectionTestControllerTest {

    @Mock WebControllerManager controllerManager;
    @Mock SBuildServer buildServer;
    @Mock ExtensionHolder extensionHolder;
    @Mock SUser adminUser;

    @TempDir File tempDir;

    private OidcConnectionTestController controller;

    @BeforeEach
    void setUp() {
        final var serverPaths = mock(ServerPaths.class);
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        final var keyManager = TestJwtKeyManagerFactory.create(serverPaths);
        lenient().when(buildServer.getRootUrl()).thenReturn("https://teamcity.example.com");
        final var issuerProvider = new OidcIssuerUrlProvider(buildServer, new OidcSettingsManager(tempDir));
        controller = new OidcConnectionTestController(
                controllerManager, keyManager, buildServer, issuerProvider,
                new jetbrains.buildServer.web.CSRFFilter(extensionHolder));
        lenient().when(adminUser.isPermissionGrantedGlobally(Permission.CHANGE_SERVER_SETTINGS)).thenReturn(true);
    }

    @Test
    public void returnsPreviewWithPlaceholderClaimsWhenNoBuildType() throws Exception {
        final var request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setParameter("audience", "api://example");
        request.setParameter("ttl_minutes", "10");
        request.setParameter("algorithm", "RS256");
        request.setParameter("subject_dimensions", "branch");

        final var response = new MockHttpServletResponse();
        controller.handlePreviewForTest(request, response, adminUser);

        final var body = response.getContentAsString();
        assertThat(body).contains("\"ok\":true");
        assertThat(body).contains("project:<project_id>:build_type:<build_type_id>:branch:<branch>");
        // net.minidev.json escapes forward slashes in strings, so api://example becomes api:\/\/example
        assertThat(body).contains("api:\\/\\/example");
    }

    @Test
    public void returnsPreviewWithResolvedClaimsWhenBuildTypeProvided() throws Exception {
        final var buildType = mock(SBuildType.class);
        when(buildType.getInternalId()).thenReturn("bt42");
        when(buildType.getProjectId()).thenReturn("project7");
        final var projectManager = mock(ProjectManager.class);
        when(buildServer.getProjectManager()).thenReturn(projectManager);
        when(projectManager.findBuildTypeByExternalId("MyBuild")).thenReturn(buildType);
        when(adminUser.isPermissionGrantedForProject("project7", Permission.EDIT_PROJECT)).thenReturn(true);

        final var request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setParameter("audience", "api://example");
        request.setParameter("ttl_minutes", "10");
        request.setParameter("algorithm", "RS256");
        request.setParameter("subject_dimensions", "");
        request.setParameter("buildTypeExternalId", "MyBuild");

        final var response = new MockHttpServletResponse();
        controller.handlePreviewForTest(request, response, adminUser);

        final var body = response.getContentAsString();
        assertThat(body).contains("project:project7:build_type:bt42");
    }

    @Test
    public void rejectsInvalidAlgorithm() throws Exception {
        final var request = new MockHttpServletRequest();
        request.setMethod("POST");
        request.setParameter("audience", "api://example");
        request.setParameter("ttl_minutes", "10");
        request.setParameter("algorithm", "HS256");
        request.setParameter("subject_dimensions", "");

        final var response = new MockHttpServletResponse();
        controller.handlePreviewForTest(request, response, adminUser);

        assertThat(response.getContentAsString()).contains("\"ok\":false");
        assertThat(response.getContentAsString()).contains("algorithm");
    }
}
