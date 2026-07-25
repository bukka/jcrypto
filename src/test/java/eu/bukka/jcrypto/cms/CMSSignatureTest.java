package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSSignatureOptions;
import eu.bukka.jcrypto.test.CommonTest;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
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
import java.nio.file.Files;
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

class CMSSignatureTest extends CommonTest {
    private static final byte[] CONTENT = "Some CMS content to sign and verify.".getBytes();

    @TempDir
    File tempDir;

    private int fileCounter = 0;

    // --- roundtrip helpers ----------------------------------------------------

    private CMSSignatureOptions signOptions(Identity signer) {
        CMSSignatureOptions options = mock(CMSSignatureOptions.class);
        when(options.getForm()).thenReturn("DER");
        when(options.getSignerCertificateFile()).thenReturn(signer.certFile);
        when(options.getPrivateKeyFile()).thenReturn(signer.keyFile);
        return options;
    }

    private CMSSignatureOptions verifyOptions() {
        CMSSignatureOptions options = mock(CMSSignatureOptions.class);
        when(options.getForm()).thenReturn("DER");
        return options;
    }

    private byte[] sign(CMSSignatureOptions options, byte[] content) throws Exception {
        when(options.getInputData()).thenReturn(content);
        ArgumentCaptor<byte[]> signed = ArgumentCaptor.forClass(byte[].class);
        new CMSSignature(options).sign();
        verify(options).writeOutputData(signed.capture());
        return signed.getValue();
    }

    private byte[] verifyContent(CMSSignatureOptions options, byte[] signed) throws Exception {
        when(options.getInputData()).thenReturn(signed);
        ArgumentCaptor<byte[]> content = ArgumentCaptor.forClass(byte[].class);
        new CMSSignature(options).verify();
        verify(options).writeOutputData(content.capture());
        return content.getValue();
    }

    private void assertRoundTrip(String keyType) throws Exception {
        Identity signer = newIdentity(keyType);
        byte[] signed = sign(signOptions(signer), CONTENT);
        // The signer certificate is embedded, so verification needs no external certificate.
        assertArrayEquals(CONTENT, verifyContent(verifyOptions(), signed));
    }

    // --- basic algorithms -----------------------------------------------------

    @Test
    void signVerifyRsa() throws Exception {
        assertRoundTrip("RSA");
    }

    @Test
    void signVerifyEc() throws Exception {
        assertRoundTrip("EC");
    }

    @Test
    void signVerifyDsa() throws Exception {
        assertRoundTrip("DSA");
    }

    @Test
    void signVerifyEd25519() throws Exception {
        assertRoundTrip("Ed25519");
    }

    @Test
    void signVerifyEd448() throws Exception {
        assertRoundTrip("Ed448");
    }

    @Test
    void ed448UsesRfc8419Shake256LenDigest() throws Exception {
        // RFC 8419: when signing with Ed448 the digestAlgorithm MUST be id-shake256-len with the
        // parameters present and set to 512.
        Identity signer = newIdentity("Ed448");
        byte[] signed = sign(signOptions(signer), CONTENT);

        SignerInformation signerInfo = new CMSSignedData(signed).getSignerInfos().getSigners().iterator().next();
        AlgorithmIdentifier digestAlgorithm = signerInfo.getDigestAlgorithmID();
        assertEquals(NISTObjectIdentifiers.id_shake256_len, digestAlgorithm.getAlgorithm());
        assertEquals(512, ASN1Integer.getInstance(digestAlgorithm.getParameters()).intValueExact());
    }

    // --- digest selection -----------------------------------------------------

    @Test
    void signUsesConfiguredDigest() throws Exception {
        Identity signer = newIdentity("RSA");
        CMSSignatureOptions options = signOptions(signer);
        when(options.getDigestAlgorithm()).thenReturn("sha512");
        byte[] signed = sign(options, CONTENT);

        SignerInformation signerInfo = new CMSSignedData(signed).getSignerInfos().getSigners().iterator().next();
        assertEquals(NISTObjectIdentifiers.id_sha512.getId(), signerInfo.getDigestAlgOID());
        assertArrayEquals(CONTENT, verifyContent(verifyOptions(), signed));
    }

    // --- detached -------------------------------------------------------------

    @Test
    void signVerifyDetached() throws Exception {
        Identity signer = newIdentity("EC");
        CMSSignatureOptions signOptions = signOptions(signer);
        when(signOptions.isDetached()).thenReturn(true);
        byte[] signed = sign(signOptions, CONTENT);

        File contentFile = writeContent(CONTENT);
        CMSSignatureOptions verifyOptions = verifyOptions();
        when(verifyOptions.isDetached()).thenReturn(true);
        when(verifyOptions.getContentFile()).thenReturn(contentFile);
        assertArrayEquals(CONTENT, verifyContent(verifyOptions, signed));
    }

    @Test
    void verifyDetachedWithoutContentThrows() throws Exception {
        Identity signer = newIdentity("EC");
        CMSSignatureOptions signOptions = signOptions(signer);
        when(signOptions.isDetached()).thenReturn(true);
        byte[] signed = sign(signOptions, CONTENT);

        CMSSignatureOptions verifyOptions = verifyOptions();
        when(verifyOptions.isDetached()).thenReturn(true);
        CMSException exception = assertThrows(CMSException.class,
                () -> new CMSSignature(verifyOptions).verify());
        assertEquals("--content is required to verify a detached signature", exception.getMessage());
    }

    // --- verifying against an explicit certificate ----------------------------

    @Test
    void verifyWithProvidedSignerCertificate() throws Exception {
        Identity signer = newIdentity("RSA");
        byte[] signed = sign(signOptions(signer), CONTENT);

        CMSSignatureOptions verifyOptions = verifyOptions();
        when(verifyOptions.getSignerCertificateFile()).thenReturn(signer.certFile);
        assertArrayEquals(CONTENT, verifyContent(verifyOptions, signed));
    }

    @Test
    void verifyWithWrongCertificateThrows() throws Exception {
        Identity signer = newIdentity("RSA");
        Identity other = newIdentity("RSA");
        byte[] signed = sign(signOptions(signer), CONTENT);

        CMSSignatureOptions verifyOptions = verifyOptions();
        when(verifyOptions.getInputData()).thenReturn(signed);
        when(verifyOptions.getSignerCertificateFile()).thenReturn(other.certFile);
        CMSException exception = assertThrows(CMSException.class,
                () -> new CMSSignature(verifyOptions).verify());
        assertEquals("Verification failure", exception.getMessage());
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
        X509Certificate certificate = selfSignedCertificate(keyPair, signatureAlgorithm(keyType));
        return new Identity(writeCertificate(certificate), writePrivateKey(keyPair.getPrivate()));
    }

    private String signatureAlgorithm(String keyType) {
        switch (keyType) {
            case "RSA":
                return "SHA256withRSA";
            case "EC":
                return "SHA256withECDSA";
            case "DSA":
                return "SHA256withDSA";
            case "Ed25519":
                return "Ed25519";
            case "Ed448":
                return "Ed448";
            default:
                throw new IllegalArgumentException("Unsupported key type " + keyType);
        }
    }

    private KeyPair generateKeyPair(String keyType) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyType, "BC");
        switch (keyType) {
            case "EC":
                generator.initialize(new ECGenParameterSpec("prime256v1"));
                break;
            case "Ed25519":
            case "Ed448":
                break;
            default:
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

    private File writeContent(byte[] content) throws Exception {
        File file = new File(tempDir, "content-" + (fileCounter++) + ".bin");
        Files.write(file.toPath(), content);
        return file;
    }
}
