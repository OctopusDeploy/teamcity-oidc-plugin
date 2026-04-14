package com.octopus.teamcity.oidc.it;

import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;

/**
 * Trusts only the self-signed CA in integration-tests/src/test/resources/tls/ca.crt.
 * Used by test HttpClients so they can talk to Caddy over HTTPS.
 */
class TlsTrustManager {

    static SSLContext buildSslContext() throws Exception {
        final var cf = CertificateFactory.getInstance("X.509");
        try (final var in = TlsTrustManager.class.getResourceAsStream("/tls/ca.crt")) {
            if (in == null) throw new IllegalStateException("ca.crt not found on classpath");
            final var ca = cf.generateCertificate(in);

            final var ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("test-ca", ca);

            final var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            final var ctx = SSLContext.getInstance("TLS");
            ctx.init(null, tmf.getTrustManagers(), null);
            return ctx;
        }
    }
}
