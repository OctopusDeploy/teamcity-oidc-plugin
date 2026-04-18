package com.octopus.teamcity.oidc.it;

import javax.net.ssl.*;
import java.security.KeyStore;
import java.security.cert.Certificate;

/**
 * Builds an SSLContext that trusts only the provided test CA certificate.
 * Used by test HttpClients so they can talk to Caddy over HTTPS.
 */
class TlsTrustManager {

    static SSLContext buildSslContext(Certificate caCert) throws Exception {
        final var ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("test-ca", caCert);

        final var tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        final var ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        return ctx;
    }
}
