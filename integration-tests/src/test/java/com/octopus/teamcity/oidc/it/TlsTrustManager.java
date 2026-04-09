package com.octopus.teamcity.oidc.it;

import javax.net.ssl.*;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Trusts only the self-signed CA in integration-tests/src/test/resources/tls/ca.crt.
 * Used by test HttpClients so they can talk to Caddy over HTTPS.
 */
class TlsTrustManager {

    static SSLContext buildSslContext() throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = TlsTrustManager.class.getResourceAsStream("/tls/ca.crt")) {
            if (in == null) throw new IllegalStateException("ca.crt not found on classpath");
            final var ca = cf.generateCertificate(in);

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("test-ca", ca);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        }
    }
}
