package systems.hugmesh.gateway.testsupport;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * REUSABLE multi-issuer test fixture — the cornerstone of the copyable multi-issuer
 * security-slice pattern (see {@code docs/testing/MULTI-ISSUER-SLICE.md}).
 *
 * <p>Each {@code TestIssuer} stands up a tiny in-process HTTP server (JDK
 * {@link HttpServer}, bound to {@code 127.0.0.1}) that serves exactly what Spring
 * Security's {@code ReactiveJwtDecoders.fromIssuerLocation(...)} needs to validate
 * a brand's tokens with NO real Casdoor and NO network egress:
 *
 * <ul>
 *   <li>{@code GET /.well-known/openid-configuration} — the OIDC discovery doc
 *       (just enough: {@code issuer} + {@code jwks_uri});</li>
 *   <li>{@code GET /.well-known/jwks.json} — the brand's PUBLIC JWK set.</li>
 * </ul>
 *
 * <p>{@link #issuerUri()} is the value you put in {@code app.tenancy.issuers}
 * (issuer=domain). {@link #mint(String, List)} mints an RSA-signed JWT whose
 * {@code iss} is this server's issuer URI — so a token minted by issuer A is
 * cryptographically valid ONLY against issuer A's manager, which is exactly the
 * cross-brand isolation the slice asserts.
 *
 * <p>Deterministic: a fresh RSA keypair per instance, fixed loopback host, OS-picked
 * port. {@link AutoCloseable} so a try-with-resources / {@code @AfterEach} stops the
 * server. NEVER touches the network beyond {@code 127.0.0.1}.
 */
public final class TestIssuer implements AutoCloseable {

    private final RSAKey rsaKey;            // private+public — used to sign
    private final RSAKey publicKey;         // public-only — served at jwks_uri
    private final HttpServer server;
    private final String issuerUri;

    public TestIssuer() {
        try {
            this.rsaKey = new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            this.publicKey = rsaKey.toPublicJWK();
            this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            int port = server.getAddress().getPort();
            this.issuerUri = "http://127.0.0.1:" + port;

            // OIDC discovery — fromIssuerLocation fetches this first, then jwks_uri.
            server.createContext("/.well-known/openid-configuration", exchange -> {
                String body = "{"
                        + "\"issuer\":\"" + issuerUri + "\","
                        + "\"jwks_uri\":\"" + issuerUri + "/.well-known/jwks.json\""
                        + "}";
                respond(exchange, body);
            });
            // The brand's public JWK set.
            server.createContext("/.well-known/jwks.json", exchange ->
                    respond(exchange, new JWKSet(publicKey).toString()));

            server.setExecutor(null);   // default executor — fine for a test fixture
            server.start();
        } catch (JOSEException | IOException e) {
            throw new IllegalStateException("failed to start TestIssuer", e);
        }
    }

    /** The issuer URI — use as the LHS of an {@code app.tenancy.issuers} pair. */
    public String issuerUri() {
        return issuerUri;
    }

    /**
     * Mint an RSA-signed JWT whose {@code iss} is THIS issuer, carrying the Casdoor
     * {@code roles} claim shape ({@code [{"name":"admin"}, ...]}) the converter reads.
     * exp is 5 min out; subject is the given {@code subject}. The token validates
     * ONLY against this issuer's manager (cross-brand isolation).
     */
    public String mint(String subject, List<String> roleNames) {
        List<Map<String, String>> roles = roleNames.stream()
                .map(r -> Map.of("name", r))
                .toList();
        return mintWithClaims(subject, Map.of("roles", roles, "name", subject));
    }

    /**
     * Mint an ALREADY-EXPIRED RS256 token (iat 10m ago, exp 5m ago) carrying the
     * Casdoor {@code roles} claim shape — correctly signed by THIS issuer, so the
     * ONLY thing wrong is the elapsed {@code exp}. Used by the negative deny-chain
     * suite to prove the resource server rejects a stale token (401) rather than
     * forwarding it. Same role-claim shape as {@link #mint(String, List)}.
     */
    public String mintExpired(String subject, List<String> roleNames) {
        List<Map<String, String>> roles = roleNames.stream()
                .map(r -> Map.of("name", r))
                .toList();
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder cb = new JWTClaimsSet.Builder()
                    .issuer(issuerUri)
                    .subject(subject)
                    .issueTime(Date.from(now.minusSeconds(600)))
                    .expirationTime(Date.from(now.minusSeconds(300)))   // expired 5m ago
                    .claim("roles", roles)
                    .claim("name", subject);
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                    cb.build());
            jwt.sign(new RSASSASigner(rsaKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to mint expired test JWT", e);
        }
    }

    /** Mint with an arbitrary claim map (iss/iat/exp/sub are still stamped here). */
    public String mintWithClaims(String subject, Map<String, Object> claims) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder cb = new JWTClaimsSet.Builder()
                    .issuer(issuerUri)
                    .subject(subject)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(300)));
            claims.forEach(cb::claim);
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(),
                    cb.build());
            jwt.sign(new RSASSASigner(rsaKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("failed to mint test JWT", e);
        }
    }

    private static void respond(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
