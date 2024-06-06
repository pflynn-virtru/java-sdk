package io.opentdf.platform.sdk;

import com.google.gson.Gson;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.grpc.ManagedChannel;
import io.opentdf.platform.kas.AccessServiceGrpc;
import io.opentdf.platform.kas.PublicKeyRequest;
import io.opentdf.platform.kas.RewrapRequest;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import static java.lang.String.format;

public class KASClient implements SDK.KAS, AutoCloseable {

    private final Function<String, ManagedChannel> channelFactory;
    private final RSASSASigner signer;
    private final AsymDecryption decryptor;
    private final String publicKeyPEM;

    /***
     * A client that communicates with KAS
     * @param channelFactory A function that produces channels that can be used to communicate
     * @param dpopKey
     */
    public KASClient(Function <String, ManagedChannel> channelFactory, RSAKey dpopKey) {
        this.channelFactory = channelFactory;
        try {
            this.signer = new RSASSASigner(dpopKey);
        } catch (JOSEException e) {
            throw new SDKException("error creating dpop signer", e);
        }
        var encryptionKeypair = CryptoUtils.generateRSAKeypair();
        decryptor = new AsymDecryption(encryptionKeypair.getPrivate());
        publicKeyPEM = CryptoUtils.getRSAPublicKeyPEM(encryptionKeypair.getPublic());
    }

    @Override
    public String getPublicKey(Config.KASInfo kasInfo) {
        return getStub(kasInfo.URL)
                .publicKey(PublicKeyRequest.getDefaultInstance())
                .getPublicKey();
    }

    private String normalizeAddress(String urlString) {
        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            // if there is no protocol then they either gave us
            // a correct address or one we don't know how to fix
            return urlString;
        }

        // otherwise we take the specified port or default
        // based on whether the URL uses a scheme that
        // implies TLS
        int port;
        if (url.getPort() == -1) {
            if ("http".equals(url.getProtocol())) {
                port = 80;
            } else {
                port = 443;
            }
        } else {
            port = url.getPort();
        }

        return format("%s:%d", url.getHost(), port);
    }

    @Override
    public synchronized void close() {
        var entries = new ArrayList<>(stubs.values());
        stubs.clear();
        for (var entry: entries) {
            entry.channel.shutdownNow();
        }
    }

    static class RewrapRequestBody {
        String policy;
        String clientPublicKey;
        Manifest.KeyAccess keyAccess;
    }

    private static final Gson gson = new Gson();

    @Override
    public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy) {
        RewrapRequestBody body = new RewrapRequestBody();
        body.policy = policy;
        body.clientPublicKey = publicKeyPEM;
        body.keyAccess = keyAccess;
        var requestBody = gson.toJson(body);

        var claims = new JWTClaimsSet.Builder()
                .claim("requestBody", requestBody)
                .issueTime(Date.from(Instant.now()))
                .expirationTime(Date.from(Instant.now().plus(Duration.ofMinutes(1))))
                .build();

        var jws = new JWSHeader.Builder(JWSAlgorithm.RS256).build();
        SignedJWT jwt = new SignedJWT(jws, claims);
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new SDKException("error signing KAS request", e);
        }

        var request = RewrapRequest
                .newBuilder()
                .setSignedRequestToken(jwt.serialize())
                .build();
        var response = getStub(keyAccess.url).rewrap(request);
        var wrappedKey = response.getEntityWrappedKey().toByteArray();
        return decryptor.decrypt(wrappedKey);
    }

    private final HashMap<String, CacheEntry> stubs = new HashMap<>();
    private static class CacheEntry {
        final ManagedChannel channel;
        final AccessServiceGrpc.AccessServiceBlockingStub stub;
        private CacheEntry(ManagedChannel channel, AccessServiceGrpc.AccessServiceBlockingStub stub) {
            this.channel = channel;
            this.stub = stub;
        }
    }

    // make this protected so we can test the address normalization logic
    synchronized AccessServiceGrpc.AccessServiceBlockingStub getStub(String url) {
        var realAddress = normalizeAddress(url);
        if (!stubs.containsKey(realAddress)) {
            var channel = channelFactory.apply(realAddress);
            var stub = AccessServiceGrpc.newBlockingStub(channel);
            stubs.put(realAddress, new CacheEntry(channel, stub));
        }

        return stubs.get(realAddress).stub;
    }
}

