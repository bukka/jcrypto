package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import eu.bukka.jcrypto.test.CommonTest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSAuthEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.KEKRecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import java.io.File;
import java.io.FileWriter;
import java.math.BigInteger;
import java.util.Map;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CMSEnvelopeTest extends CommonTest {
    private static final byte[] CONTENT = "Some CMS content to envelope and recover.".getBytes();
    private static final String SECRET_KEY = "000102030405060708090A0B0C0D0E0F";
    private static final String SECRET_KEY_ID = "C0FEE0";

    @TempDir
    File tempDir;

    private int fileCounter = 0;

    // --- roundtrip helpers ----------------------------------------------------

    private CMSEnvelopeOptions baseOptions(String algorithm) {
        CMSEnvelopeOptions options = mock(CMSEnvelopeOptions.class);
        when(options.getForm()).thenReturn("DER");
        when(options.getAlgorithm()).thenReturn(algorithm);
        return options;
    }

    private byte[] encrypt(CMSEnvelopeOptions options, byte[] content) throws Exception {
        when(options.getInputData()).thenReturn(content);
        ArgumentCaptor<byte[]> encrypted = ArgumentCaptor.forClass(byte[].class);
        new CMSEnvelope(options).encrypt();
        verify(options).writeOutputData(encrypted.capture());
        return encrypted.getValue();
    }

    private byte[] decrypt(CMSEnvelopeOptions options, byte[] encrypted) throws Exception {
        when(options.getInputData()).thenReturn(encrypted);
        ArgumentCaptor<byte[]> decrypted = ArgumentCaptor.forClass(byte[].class);
        new CMSEnvelope(options).decrypt();
        verify(options).writeOutputData(decrypted.capture());
        return decrypted.getValue();
    }

    private void assertRoundTrip(CMSEnvelopeOptions encryptOptions, CMSEnvelopeOptions decryptOptions)
            throws Exception {
        byte[] encrypted = encrypt(encryptOptions, CONTENT);
        byte[] decrypted = decrypt(decryptOptions, encrypted);
        assertArrayEquals(CONTENT, decrypted);
    }

    // --- KEK (shared secret key) ---------------------------------------------

    private CMSEnvelopeOptions kekOptions(String algorithm, String contentType) {
        CMSEnvelopeOptions options = baseOptions(algorithm);
        when(options.getContentType()).thenReturn(contentType);
        when(options.getSecretKey()).thenReturn(SECRET_KEY);
        when(options.getSecretKeyIdentifier()).thenReturn(SECRET_KEY_ID);
        return options;
    }

    @Test
    void kekEnvelopedAes128Cbc() throws Exception {
        assertRoundTrip(kekOptions("aes-128-cbc", null), kekOptions("aes-128-cbc", null));
    }

    @Test
    void kekAuthEnvelopedAes128Gcm() throws Exception {
        assertRoundTrip(kekOptions("aes-128-gcm", null), kekOptions("aes-128-gcm", null));
    }

    @Test
    void kekKeyIdentifierIsHexDecoded() throws Exception {
        // The KEK identifier is stored hex-decoded so it matches OpenSSL's OPENSSL_hexstr2buf.
        byte[] encrypted = encrypt(kekOptions("aes-128-cbc", null), CONTENT);
        RecipientInformation recipient = new CMSEnvelopedData(encrypted)
                .getRecipientInfos().getRecipients().iterator().next();
        KEKRecipientId recipientId = (KEKRecipientId) recipient.getRID();
        assertArrayEquals(Hex.decode(SECRET_KEY_ID), recipientId.getKeyIdentifier());
    }

    @Test
    void kekEnvelopedAes128GcmWithEnvelopedContentType() throws Exception {
        // AEAD cipher forced into a plain enveloped-data structure rather than authEnveloped-data.
        assertRoundTrip(kekOptions("aes-128-gcm", "enveloped-data"),
                kekOptions("aes-128-gcm", "enveloped-data"));
    }

    // --- authEnveloped-data attributes ---------------------------------------

    private static final String AUTH_ATTR_OID = "1.3.6.1.4.1.99999.1";
    private static final String UNAUTH_ATTR_OID = "1.3.6.1.4.1.99999.2";

    private String attributeValue(Attribute attribute) {
        return DERUTF8String.getInstance(attribute.getAttributeValues()[0]).getString();
    }

    @Test
    void authEnvelopedCarriesAuthenticatedAndUnauthenticatedAttributes() throws Exception {
        CMSEnvelopeOptions encryptOptions = kekOptions("aes-128-gcm", null);
        when(encryptOptions.getAuthenticatedAttributes()).thenReturn(Map.of(AUTH_ATTR_OID, "auth-value"));
        when(encryptOptions.getUnauthenticatedAttributes()).thenReturn(Map.of(UNAUTH_ATTR_OID, "unauth-value"));
        byte[] encrypted = encrypt(encryptOptions, CONTENT);

        CMSAuthEnvelopedData authEnvelopedData = new CMSAuthEnvelopedData(encrypted);
        assertEquals("auth-value",
                attributeValue(authEnvelopedData.getAuthAttrs().get(new ASN1ObjectIdentifier(AUTH_ATTR_OID))));
        assertEquals("unauth-value",
                attributeValue(authEnvelopedData.getUnauthAttrs().get(new ASN1ObjectIdentifier(UNAUTH_ATTR_OID))));

        // attributes must not break the content roundtrip
        assertArrayEquals(CONTENT, decrypt(kekOptions("aes-128-gcm", null), encrypted));
    }

    @Test
    void envelopedDataWithAttributesThrows() {
        CMSEnvelopeOptions options = kekOptions("aes-128-cbc", null);
        when(options.getAuthenticatedAttributes()).thenReturn(Map.of(AUTH_ATTR_OID, "auth-value"));
        CMSException exception = assertThrows(CMSException.class, () -> encrypt(options, CONTENT));
        assertEquals("Attributes are only supported for authEnveloped-data", exception.getMessage());
    }

    // --- KeyTrans (RSA certificate) ------------------------------------------

    private CMSEnvelopeOptions keyTransOptions(String algorithm, Identity recipient) {
        CMSEnvelopeOptions options = baseOptions(algorithm);
        when(options.getCertificateFile()).thenReturn(recipient.certFile);
        when(options.getPrivateKeyFile()).thenReturn(recipient.keyFile);
        return options;
    }

    @Test
    void keyTransEnvelopedAes128Cbc() throws Exception {
        Identity recipient = newIdentity("RSA");
        assertRoundTrip(keyTransOptions("aes-128-cbc", recipient),
                keyTransOptions("aes-128-cbc", recipient));
    }

    @Test
    void keyTransAuthEnvelopedAes256Gcm() throws Exception {
        Identity recipient = newIdentity("RSA");
        assertRoundTrip(keyTransOptions("aes-256-gcm", recipient),
                keyTransOptions("aes-256-gcm", recipient));
    }

    // --- KeyAgree (EC certificates) ------------------------------------------

    private CMSEnvelopeOptions keyAgreeEncryptOptions(String algorithm, Identity sender, Identity recipient) {
        CMSEnvelopeOptions options = baseOptions(algorithm);
        when(options.getSenderCertificateFile()).thenReturn(sender.certFile);
        when(options.getPrivateKeyFile()).thenReturn(sender.keyFile);
        when(options.getRecipientCertificateFile()).thenReturn(recipient.certFile);
        return options;
    }

    private CMSEnvelopeOptions keyAgreeDecryptOptions(String algorithm, Identity recipient) {
        CMSEnvelopeOptions options = baseOptions(algorithm);
        when(options.getRecipientCertificateFile()).thenReturn(recipient.certFile);
        when(options.getPrivateKeyFile()).thenReturn(recipient.keyFile);
        return options;
    }

    @Test
    void keyAgreeEnvelopedAes128Cbc() throws Exception {
        Identity sender = newIdentity("EC");
        Identity recipient = newIdentity("EC");
        assertRoundTrip(keyAgreeEncryptOptions("aes-128-cbc", sender, recipient),
                keyAgreeDecryptOptions("aes-128-cbc", recipient));
    }

    @Test
    void keyAgreeAuthEnvelopedAes128Gcm() throws Exception {
        Identity sender = newIdentity("EC");
        Identity recipient = newIdentity("EC");
        assertRoundTrip(keyAgreeEncryptOptions("aes-128-gcm", sender, recipient),
                keyAgreeDecryptOptions("aes-128-gcm", recipient));
    }

    // --- error handling -------------------------------------------------------

    @Test
    void encryptWithoutRecipientOptionsThrows() {
        CMSEnvelopeOptions options = baseOptions("aes-128-cbc");
        CMSException exception = assertThrows(CMSException.class, () -> new CMSEnvelope(options).encrypt());
        assertEquals("No options to create recipient info", exception.getMessage());
    }

    // --- test key/certificate generation -------------------------------------

    private static class Identity {
        final File certFile;
        final File keyFile;

        Identity(File certFile, File keyFile) {
            this.certFile = certFile;
            this.keyFile = keyFile;
        }
    }

    private Identity newIdentity(String keyType) throws Exception {
        KeyPair keyPair = generateKeyPair(keyType);
        String signatureAlgorithm = keyType.equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
        X509Certificate certificate = selfSignedCertificate(keyPair, signatureAlgorithm);
        return new Identity(writeCertificate(certificate), writePrivateKey(keyPair.getPrivate()));
    }

    private KeyPair generateKeyPair(String keyType) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyType, "BC");
        if (keyType.equals("EC")) {
            generator.initialize(new ECGenParameterSpec("prime256v1"));
        } else {
            generator.initialize(2048);
        }
        return generator.generateKeyPair();
    }

    private X509Certificate selfSignedCertificate(KeyPair keyPair, String signatureAlgorithm) throws Exception {
        X500Name name = new X500Name("CN=jcrypto-test");
        long now = System.currentTimeMillis();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(now), new Date(now - 86400000L), new Date(now + 86400000L),
                name, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                .setProvider("BC").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private File writeCertificate(X509Certificate certificate) throws Exception {
        File file = new File(tempDir, "cert-" + (fileCounter++) + ".pem");
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(file))) {
            writer.writeObject(certificate);
        }
        return file;
    }

    private File writePrivateKey(PrivateKey key) throws Exception {
        File file = new File(tempDir, "key-" + (fileCounter++) + ".pem");
        try (PemWriter writer = new PemWriter(new FileWriter(file))) {
            writer.writeObject(new PemObject("PRIVATE KEY", key.getEncoded()));
        }
        return file;
    }
}
