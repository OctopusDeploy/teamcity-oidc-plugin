package com.octopus.teamcity.oidc.it;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/**
 * Generates a self-signed test CA and a server certificate at test startup.
 * Keeps private keys out of source control.
 */
class TlsCertificateGenerator {

    record Result(
            X509Certificate caCert,
            Path caCertPem,
            Path serverCertPem,
            Path serverKeyPem
    ) {}

    /**
     * Generates a CA and a server certificate with SANs for each of the given hostnames.
     * Files are written to a temp directory that lives for the duration of the JVM.
     */
    static Result generate(String... serverHostnames) throws Exception {
        final var kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);

        final var notBefore = Date.from(Instant.now().minus(1, ChronoUnit.DAYS));
        final var notAfter  = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        final var caName    = new X500Name("CN=Test CA");

        // CA keypair + self-signed cert
        final var caKeyPair  = kpg.generateKeyPair();
        final var caBuilder  = new JcaX509v3CertificateBuilder(
                caName, BigInteger.ONE, notBefore, notAfter, caName, caKeyPair.getPublic());
        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        final var caSigner   = new JcaContentSignerBuilder("SHA256WithRSA").build(caKeyPair.getPrivate());
        final var caCert     = new JcaX509CertificateConverter().getCertificate(caBuilder.build(caSigner));

        // Server keypair + cert signed by the CA
        final var serverKeyPair  = kpg.generateKeyPair();
        final var serverName     = new X500Name("CN=" + serverHostnames[0]);
        final var serverBuilder  = new JcaX509v3CertificateBuilder(
                caName, BigInteger.TWO, notBefore, notAfter, serverName, serverKeyPair.getPublic());
        final var sans = new GeneralName[serverHostnames.length];
        for (int i = 0; i < serverHostnames.length; i++) {
            sans[i] = new GeneralName(GeneralName.dNSName, serverHostnames[i]);
        }
        serverBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(sans));
        final var serverSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(caKeyPair.getPrivate());
        final var serverCert   = new JcaX509CertificateConverter().getCertificate(serverBuilder.build(serverSigner));

        // Write PEM files to a temp directory
        final var dir           = Files.createTempDirectory("tls-");
        final var caCertPem     = dir.resolve("ca.crt");
        final var serverCertPem = dir.resolve("server.crt");
        final var serverKeyPem  = dir.resolve("server.key");

        Files.writeString(caCertPem,     toPem("CERTIFICATE", caCert.getEncoded()));
        Files.writeString(serverCertPem, toPem("CERTIFICATE", serverCert.getEncoded()));
        Files.writeString(serverKeyPem,  toPem("PRIVATE KEY", serverKeyPair.getPrivate().getEncoded()));

        return new Result(caCert, caCertPem, serverCertPem, serverKeyPem);
    }

    private static String toPem(String type, byte[] data) {
        return "-----BEGIN " + type + "-----\n" +
               Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(data) +
               "\n-----END " + type + "-----\n";
    }
}
