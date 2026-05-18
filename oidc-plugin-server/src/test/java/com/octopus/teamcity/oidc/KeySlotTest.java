package com.octopus.teamcity.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class KeySlotTest {

    @Test
    void rejectsNullJwk() {
        assertThatThrownBy(() -> new KeySlot(null, Instant.EPOCH))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("jwk");
    }

    @Test
    void rejectsNullActivateAt() throws JOSEException {
        final var jwk = freshRsa();
        assertThatThrownBy(() -> new KeySlot(jwk, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("activateAt");
    }

    @Test
    void isActiveAtReturnsTrueWhenActivateAtIsPast() throws JOSEException {
        final var slot = new KeySlot(freshRsa(), Instant.now().minusSeconds(60));
        assertThat(slot.isActiveAt(Instant.now())).isTrue();
    }

    @Test
    void isActiveAtReturnsFalseWhenActivateAtIsFuture() throws JOSEException {
        final var slot = new KeySlot(freshRsa(), Instant.now().plusSeconds(60));
        assertThat(slot.isActiveAt(Instant.now())).isFalse();
    }

    @Test
    void isActiveAtReturnsTrueAtExactBoundary() throws JOSEException {
        final var t = Instant.now();
        final var slot = new KeySlot(freshRsa(), t);
        assertThat(slot.isActiveAt(t)).isTrue();
    }

    private static com.nimbusds.jose.jwk.RSAKey freshRsa() throws JOSEException {
        return new RSAKeyGenerator(2048)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint(true)
                .generate();
    }
}
