package de.ndr.teamcity;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.gson.JsonArray;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.shaded.gson.JsonParser;
import jetbrains.buildServer.serverSide.ServerPaths;
import jetbrains.buildServer.web.openapi.PluginDescriptor;
import jetbrains.buildServer.web.openapi.WebControllerManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class KeyRotationTest {

    @Mock
    private WebControllerManager controllerManager;

    @Mock
    private ServerPaths serverPaths;

    @Mock
    private PluginDescriptor pluginDescriptor;

    @Mock
    private jetbrains.buildServer.serverSide.SBuildServer buildServer;

    @TempDir
    private File tempDir;

    @Test
    public void rotationGeneratesNewRsaAndEcKeys() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        RSAKey originalRsa = jwtBuildFeature.getRsaKey();
        ECKey originalEc = jwtBuildFeature.getEcKey();

        jwtBuildFeature.rotateKey();

        assertThat(jwtBuildFeature.getRsaKey().getKeyID()).isNotEqualTo(originalRsa.getKeyID());
        assertThat(jwtBuildFeature.getEcKey().getKeyID()).isNotEqualTo(originalEc.getKeyID());
    }

    @Test
    public void jwksContainsCurrentAndRetiredKeysAfterRotation() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        RSAKey originalRsa = jwtBuildFeature.getRsaKey();
        ECKey originalEc = jwtBuildFeature.getEcKey();

        jwtBuildFeature.rotateKey();
        RSAKey newRsa = jwtBuildFeature.getRsaKey();
        ECKey newEc = jwtBuildFeature.getEcKey();

        JsonArray keys = jwksKeys(jwtBuildFeature);
        // current RSA + retired RSA + current EC + retired EC
        assertThat(keys).hasSize(4);

        var kids = kidsInArray(keys);
        assertThat(kids).contains(originalRsa.getKeyID(), newRsa.getKeyID(),
                                   originalEc.getKeyID(), newEc.getKeyID());
    }

    @Test
    public void rotatingAgainRetiresPreviousRetiredKeys() throws Exception {
        when(serverPaths.getPluginDataDirectory()).thenReturn(tempDir);
        JwtBuildFeature jwtBuildFeature = new JwtBuildFeature(serverPaths, pluginDescriptor, buildServer);
        RSAKey rsa1 = jwtBuildFeature.getRsaKey();
        ECKey ec1 = jwtBuildFeature.getEcKey();

        jwtBuildFeature.rotateKey();
        RSAKey rsa2 = jwtBuildFeature.getRsaKey();
        ECKey ec2 = jwtBuildFeature.getEcKey();

        jwtBuildFeature.rotateKey();
        RSAKey rsa3 = jwtBuildFeature.getRsaKey();
        ECKey ec3 = jwtBuildFeature.getEcKey();

        JsonArray keys = jwksKeys(jwtBuildFeature);
        // current RSA3 + retired RSA2 (rsa1 dropped) + current EC3 + retired EC2 (ec1 dropped)
        assertThat(keys).hasSize(4);

        var kids = kidsInArray(keys);
        assertThat(kids).doesNotContain(rsa1.getKeyID(), ec1.getKeyID());
        assertThat(kids).contains(rsa2.getKeyID(), rsa3.getKeyID(), ec2.getKeyID(), ec3.getKeyID());
    }

    // --- helpers ---

    private JsonArray jwksKeys(JwtBuildFeature feature) throws Exception {
        JwksController controller = new JwksController(controllerManager, feature);
        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        StringWriter writer = new StringWriter();
        when(response.getWriter()).thenReturn(new PrintWriter(writer));
        controller.doHandle(request, response);
        return JsonParser.parseString(writer.toString()).getAsJsonObject().get("keys").getAsJsonArray();
    }

    private java.util.List<String> kidsInArray(JsonArray keys) {
        var kids = new java.util.ArrayList<String>();
        for (int i = 0; i < keys.size(); i++) {
            kids.add(keys.get(i).getAsJsonObject().get("kid").getAsString());
        }
        return kids;
    }
}
