package io.opentdf.platform.sdk;


import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;

import io.opentdf.platform.sdk.nanotdf.NanoTDFType;
import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.annotation.Nonnull;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class TDFTest {

    private static SDK.KAS kas = new SDK.KAS() {
        @Override
        public void close() {}

        @Override
        public String getPublicKey(Config.KASInfo kasInfo) {
            int index = Integer.parseInt(kasInfo.URL);

            return CryptoUtils.getRSAPublicKeyPEM(keypairs.get(index).getPublic());
        }

        @Override
        public String getKid(Config.KASInfo kasInfo) {
            return "r1";
        }

        @Override
        public byte[] unwrap(Manifest.KeyAccess keyAccess, String policy) {
            int index = Integer.parseInt(keyAccess.url);
            var decryptor = new AsymDecryption(keypairs.get(index).getPrivate());
            var bytes = Base64.getDecoder().decode(keyAccess.wrappedKey);
            try {
                return decryptor.decrypt(bytes);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public String getECPublicKey(Config.KASInfo kasInfo, NanoTDFType.ECCurve curve) {
            return null;
        }

        @Override
        public byte[] unwrapNanoTDF(NanoTDFType.ECCurve curve, String header, String kasURL) {
            return null;
        }
    };

    private static ArrayList<KeyPair> keypairs = new ArrayList<>();

    @BeforeAll
    static void createKeypairs() {
        for (int i = 0; i < 1 + new Random().nextInt(5); i++) {
            keypairs.add(CryptoUtils.generateRSAKeypair());
        }
    }

    @Test
    void testSimpleTDFEncryptAndDecrypt() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[32];
        secureRandom.nextBytes(key);

        var assertion1 = new AssertionConfig();
        assertion1.id = "assertion1";
        assertion1.type = AssertionConfig.Type.BaseAssertion;
        assertion1.scope = AssertionConfig.Scope.TrustedDataObj;
        assertion1.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertion1.statement = new AssertionConfig.Statement();
        assertion1.statement.format = "base64binary";
        assertion1.statement.schema = "text";
        assertion1.statement.value = "ICAgIDxlZGoOkVkaD4=";
        assertion1.assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withMetaData("here is some metadata"),
                Config.withAssertionConfig(assertion1)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.defaultKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.HS256, key);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas, assertionVerificationKeys);
        assertThat(reader.getManifest().payload.mimeType).isEqualTo("application/octet-stream");

        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
        assertThat(reader.getMetadata()).isEqualTo("here is some metadata");
    }

    @Test
    void testSimpleTDFWithAssertionWithRS256() throws Exception {

        String assertion1Id = "assertion1";
        var keypair = CryptoUtils.generateRSAKeypair();
        var assertionConfig = new AssertionConfig();
        assertionConfig.id = assertion1Id;
        assertionConfig.type = AssertionConfig.Type.BaseAssertion;
        assertionConfig.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertionConfig.statement = new AssertionConfig.Statement();
        assertionConfig.statement.format = "base64binary";
        assertionConfig.statement.schema = "text";
        assertionConfig.statement.value = "ICAgIDxlZGoOkVkaD4=";
        assertionConfig.assertionKey = new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256,
                keypair.getPrivate());

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withAssertionConfig(assertionConfig)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var assertionVerificationKeys = new Config.AssertionVerificationKeys();
        assertionVerificationKeys.keys.put(assertion1Id,
                new AssertionConfig.AssertionKey(AssertionConfig.AssertionKeyAlg.RS256, keypair.getPublic()));

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas, assertionVerificationKeys);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }

    @Test
    void testSimpleTDFWithAssertionWithHS256() throws Exception {

        String assertion1Id = "assertion1";
        var assertionConfig1 = new AssertionConfig();
        assertionConfig1.id = assertion1Id;
        assertionConfig1.type = AssertionConfig.Type.HandlingAssertion;
        assertionConfig1.scope = AssertionConfig.Scope.TrustedDataObj;
        assertionConfig1.appliesToState = AssertionConfig.AppliesToState.Unencrypted;
        assertionConfig1.statement = new AssertionConfig.Statement();
        assertionConfig1.statement.format = "base64binary";
        assertionConfig1.statement.schema = "text";
        assertionConfig1.statement.value = "ICAgIDxlZGoOkVkaD4=";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withAssertionConfig(assertionConfig1)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toString(StandardCharsets.UTF_8))
                .withFailMessage("extracted data does not match")
                .isEqualTo(plainText);
    }

    @Test
    public void testCreatingTDFWithMultipleSegments() throws Exception {
        var random = new Random();

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                // use a random segment size that makes sure that we will use multiple segments
                Config.withSegmentSize(1 + random.nextInt(20))
        );

        // data should be bigger than the largest segment
        var data = new byte[21 + random.nextInt(2048)];
        random.nextBytes(data);
        var plainTextInputStream = new ByteArrayInputStream(data);
        var tdfOutputStream = new ByteArrayOutputStream();
        var tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);
        var unwrappedData = new ByteArrayOutputStream();
        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas);
        reader.readPayload(unwrappedData);

        assertThat(unwrappedData.toByteArray())
                .withFailMessage("extracted data does not match")
                .containsExactly(data);

    }

    @Test
    public void testCreatingTooLargeTDF() {
        var random = new Random();
        var maxSize = random.nextInt(1024);
        var numReturned = new AtomicInteger(0);

        // return 1 more byte than the maximum size
        var is = new InputStream() {
            @Override
            public int read() {
                if (numReturned.get() > maxSize) {
                    return -1;
                }
                numReturned.incrementAndGet();
                return 1;
            }

            @Override
            public int read(byte[] b, int off, int len) {
                var numToReturn = Math.min(len, maxSize - numReturned.get() + 1);
                numReturned.addAndGet(numToReturn);
                return numToReturn;
            }
        };

        var os = new OutputStream() {
            @Override
            public void write(int b) {}
            @Override
            public void write(byte[] b, int off, int len) {}
        };

        var tdf = new TDF(maxSize);
        var tdfConfig = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withSegmentSize(1 + random.nextInt(128)));
        assertThrows(TDF.DataSizeNotSupported.class,
                () -> tdf.createTDF(is, os, tdfConfig, kas),
                "didn't throw an exception when we created TDF that was too large");
        assertThat(numReturned.get())
                .withFailMessage("test returned the wrong number of bytes")
                .isEqualTo(maxSize + 1);
    }

    @Test
    public void testCreateTDFWithMimeType() throws Exception {

        final String mimeType = "application/pdf";

        Config.TDFConfig config = Config.newTDFConfig(
                Config.withKasInformation(getKASInfos()),
                Config.withMimeType(mimeType)
        );

        String plainText = "this is extremely sensitive stuff!!!";
        InputStream plainTextInputStream = new ByteArrayInputStream(plainText.getBytes());
        ByteArrayOutputStream tdfOutputStream = new ByteArrayOutputStream();

        TDF tdf = new TDF();
        tdf.createTDF(plainTextInputStream, tdfOutputStream, config, kas);

        var reader = tdf.loadTDF(new SeekableInMemoryByteChannel(tdfOutputStream.toByteArray()), kas);
        assertThat(reader.getManifest().payload.mimeType).isEqualTo(mimeType);
    }

    @Nonnull
    private static Config.KASInfo[] getKASInfos() {
        var kasInfos = new ArrayList<>();
        for (int i = 0; i < keypairs.size(); i++) {
            var kasInfo = new Config.KASInfo();
            kasInfo.URL = Integer.toString(i);
            kasInfo.PublicKey = null;
            kasInfos.add(kasInfo);
        }
        return kasInfos.toArray(Config.KASInfo[]::new);
    }
}
