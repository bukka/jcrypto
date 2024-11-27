package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorException;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;

public class KeyGeneratorEnvelope extends PKeyEnvelope {

    public KeyGeneratorEnvelope(PKeyOptions options) {
        super(options);
    }

    public void generate() throws GeneralSecurityException, IOException, OperatorException {
        KeyPair keyPair = generateKeyPair();
        if (keyPair == null) {
            throw new GeneralSecurityException("KeyPair generation failed");
        }
        saveKeyPair(keyPair);
    }


    private KeyPair generateKeyPair() throws GeneralSecurityException, IOException {
        String algorithm = options.getAlgorithm();
        String parameters = options.getParameters();
        Provider provider = options.getProvider();

        KeyPairGenerator keyPairGenerator;

        try {
            if (provider != null) {
                loadKeyStore();
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
            } else {
                keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            }
        } catch (NoSuchAlgorithmException e) {
            if (provider != null) {
                System.out.println("Provider: " + provider.getName());
                provider.getServices().forEach(service -> System.out.println(service.getType() + ": " + service.getAlgorithm()));
            }
            throw e;
        } catch (GeneralSecurityException|IOException e) {
            throw e;
        }

        if ("EC".equalsIgnoreCase(algorithm) && parameters != null) {
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(parameters);
            keyPairGenerator.initialize(ecSpec);
        } else if (parameters != null) {
            int keySize = Integer.parseInt(parameters);
            keyPairGenerator.initialize(keySize);
        }

        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws GeneralSecurityException, CertIOException {
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365L * 24 * 60 * 60 * 1000); // 1 year validity

        X500Name issuer = new X500Name("CN=Self-Signed");
        BigInteger serialNumber = BigInteger.valueOf(now);

        // Create certificate builder
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serialNumber,
                startDate,
                endDate,
                issuer,
                keyPair.getPublic()
        );

        certBuilder.addExtension(
                org.bouncycastle.asn1.x509.Extension.basicConstraints,
                true,
                new org.bouncycastle.asn1.x509.BasicConstraints(true) // CA=true for self-signed certificates
        );

        // Use custom ContentSigner for PKCS#11
        ContentSigner contentSigner = new ContentSigner() {
            private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            private final Signature signature = Signature.getInstance("SHA256withECDSA", options.getProvider());

            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        new ASN1ObjectIdentifier("1.2.840.10045.4.3.2")
                );
            }

            @Override
            public OutputStream getOutputStream() {
                return outputStream;
            }

            @Override
            public byte[] getSignature() {
                try {
                    signature.initSign(keyPair.getPrivate());
                    signature.update(outputStream.toByteArray());
                    return signature.sign();
                } catch (Exception e) {
                    throw new RuntimeException("Error signing data", e);
                }
            }
        };

        // Build and convert the certificate
        X509CertificateHolder certHolder = certBuilder.build(contentSigner);
        return new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certHolder);
    }

    private void saveKeyPair(KeyPair keyPair) throws IOException, GeneralSecurityException {
        if (options.getPublicKeyFile() != null) {
            saveKeyToFile(keyPair.getPublic(), options.getPublicKeyFile());
        }
        if (options.getProvider() != null && options.getProviderName().equalsIgnoreCase("SunPKCS11")) {
            String alias = options.getPrivateKeyAlias();
            if (alias == null) {
                throw new SecurityException("Alias is required for PKCS#11 key store");
            }
            String keyStorePassword = options.getKeyStorePassword();
            char[] keyStorePasswordChars = keyStorePassword != null ? keyStorePassword.toCharArray() : null;
            loadKeyStore();
            X509Certificate certificate = generateSelfSignedCertificate(keyPair);
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyStorePasswordChars, new X509Certificate[]{certificate});
        } else {
            // Save both private key only for non-PKCS#11 providers
            if (options.getPrivateKeyFile() != null) {
                saveKeyToFile(keyPair.getPrivate(), options.getPrivateKeyFile());
            }
        }
    }

    private void saveKeyToFile(Key key, File file) throws IOException {
        if (key == null) {
            throw new IOException("Key is null, cannot save to file");
        }
        options.writeData(file, key.getEncoded());
    }
}
