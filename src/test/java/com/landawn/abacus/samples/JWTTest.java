package com.landawn.abacus.samples;

import java.util.Map;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.JsonWebKeySet;
import org.jose4j.jwk.VerificationJwkSelector;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.junit.jupiter.api.Test;

import com.landawn.abacus.http.HttpRequest;
import com.landawn.abacus.util.N;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWKSecurityContext;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

class JWTTest extends TestBase {

    // The complete JWT representation, or compact serialization, is string consisting of
    // three dot ('.') separated base64url-encoded parts in the form Header.Payload.Signature 
    static final String jwt = "eyJraWQiOiJVcG1aRWlXVndlRDJXK2Q5aHd0SkJxS2ppQWowOWs3dU1vRFRhUXoxWUFBPSIsImFsZyI6IlJTMjU2In0"
            + ".eyJzdWIiOiI1Y2RhMmM2MS01Yjk2LTRhOTQtYWVjNS05NzQwMmQwYWVhMzEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfcFNjaEtCYnFvIiwicGhvbmVfbnVtYmVyX3ZlcmlmaWVkIjpmYWxzZSwiY29nbml0bzp1c2VybmFtZSI6ImhlY2hlbiIsImF1ZCI6IjM0MGY0ZGYzZGxjOXRsaDdsbnZramw0dmJuIiwiZXZlbnRfaWQiOiIwMjdkMzQ4OC0zOWQ2LTQyMjMtYWJjNy01OTk4MjA4ZDc1YTIiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTU4NzEwMDY0NSwicGhvbmVfbnVtYmVyIjoiKzE0MDg1MDc5ODMzIiwiZXhwIjoxNTg3MjM2ODk3LCJpYXQiOjE1ODcyMzMyOTcsImVtYWlsIjoiZHJvcHJpbmNlQGdtYWlsLmNvbSJ9"
            + ".DJAQjrB9D2b3qs2EwR4Ts1xIi6azaQyXX4QSZQFaN3bUT9nIx-S2zzvOmInkn88mHhKlQ9FfuyVLrKE2C3SUOo9CE3sK6N26U7CM_RJiVqSh5IaUyRueD_9DShL1YvAfO_H8sIBTfQ6f6fmRarCoOIiD5b74kyYPxLnLkbDnxZFFuHlT8rydhNN9wKIxRE7D1H9ZLf8KJDbCw1m6TxiWDVB1qenD94aYdJXZO49QaGxGVVxLT6RGJQZiu22g6HR8El91K86hGkDgWY7b_u8kKawerC5remtRIUUSTSaIQnYiBa7M52MJ9jROxj0rxZwGfoudts3aTckcD7h7zk0A4w";

    static final String jwks;
    static {
        final String[] parts = jwt.split("\\.");
        Map<String, String> header = N.fromJSON(Map.class, N.base64DecodeToString(parts[0]));
        Map<String, String> payload = N.fromJSON(Map.class, N.base64DecodeToString(parts[1]));

        N.println(N.toJSON(header, true));
        N.println(N.toJSON(payload, true));

        N.println("====================================================");
        jwks = HttpRequest.url(payload.get("iss") + "/.well-known/jwks.json").get();
        N.println(N.formatJSON(jwks));
    }

    @Test
    public void test_jose4j() throws Exception {
        // Create a new JsonWebSignature object
        JsonWebSignature jws = new JsonWebSignature();

        // Set the algorithm constraints based on what is agreed upon or expected from the sender
        jws.setAlgorithmConstraints(new AlgorithmConstraints(ConstraintType.WHITELIST, AlgorithmIdentifiers.RSA_USING_SHA256));

        // Set the compact serialization on the JWS
        jws.setCompactSerialization(jwt);

        // Create a new JsonWebKeySet object with the JWK Set JSON
        JsonWebKeySet jsonWebKeySet = new JsonWebKeySet(jwks);

        // The JWS header contains information indicating which key was used to secure the JWS.
        // In this case (as will hopefully often be the case) the JWS Key ID
        // corresponds directly to the Key ID in the JWK Set.
        // The VerificationJwkSelector looks at Key ID, Key Type, designated use (signatures vs. encryption),
        // and the designated algorithm in order to select the appropriate key for verification from
        // a set of JWKs.
        VerificationJwkSelector jwkSelector = new VerificationJwkSelector();
        JsonWebKey jwk = jwkSelector.select(jws, jsonWebKeySet.getJsonWebKeys());

        // The verification key on the JWS is the public key from the JWK we pulled from the JWK Set.
        jws.setKey(jwk.getKey());

        // Check the signature
        boolean signatureVerified = jws.verifySignature();

        // Do something useful with the result of signature verification
        System.out.println("JWS Signature is valid: " + signatureVerified);

        // Get the payload, or signed content, from the JWS
        String payload = jws.getPayload();

        // Do something useful with the content
        System.out.println("JWS payload: " + payload);
    }

    @Test
    public void test_nimbusds() throws Exception {
        ConfigurableJWTProcessor<JWKSecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        JWSAlgorithm jwsAlgorithm = JWSAlgorithm.RS256;
        JWKSource<JWKSecurityContext> jwkSource = new ImmutableJWKSet<>(JWKSet.parse(jwks));
        JWSKeySelector<JWKSecurityContext> keySelector = new JWSVerificationKeySelector<>(jwsAlgorithm, jwkSource);
        jwtProcessor.setJWSKeySelector(keySelector);
        JWTClaimsSet claimsSet = jwtProcessor.process(jwt, null);
        N.println(claimsSet);
    }
}
