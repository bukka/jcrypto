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

    public byte[] generate(String keyName) throws GeneralSecurityException, IOException, OperatorException {
        KeyPair keyPair = generateKeyPair();
        if (keyPair == null) {
            throw new GeneralSecurityException("KeyPair generation failed");
        }
        return saveKeyPair(keyPair, keyName);
    }

    public void generate() throws GeneralSecurityException, IOException, OperatorException {
        generate(null);
    }

    private KeyPair generateKeyPair() throws GeneralSecurityException, IOException {
        String algorithm = getBaseAlgorithm(options.getAlgorithm());
        String parameters = options.getParameters();
        Provider provider = options.getProvider();

        KeyPairGenerator keyPairGenerator;
        if (provider != null) {
            loadKeyStore();
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm, provider);
        } else {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
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

    private byte[] saveKeyPair(KeyPair keyPair, String keyName) throws IOException, GeneralSecurityException {
        byte[] publicKeyEncodedData = null;
        if (options.getPublicKeyFile() != null) {
            PublicKey publicKey = keyPair.getPublic();
            if (publicKey == null) {
                throw new IOException("Public key is null, cannot save to file");
            }
            publicKeyEncodedData = publicKey.getEncoded();
            File publicKeyFile = options.getPublicKeyFile();
            if (publicKeyFile != null) {
                options.writeData(publicKeyFile, publicKeyEncodedData);
            }
        }
        if (options.getProvider() != null && options.getProviderName().equalsIgnoreCase("SunPKCS11")) {
            String alias = options.getPrivateKeyAlias();
            if (alias == null) {
                if (keyName == null) {
                    throw new SecurityException("Alias is required for PKCS#11 key store");
                }
                alias = keyName;
            } else if (keyName != null) {
                alias = alias + "-" + keyName;
            }
            String keyStorePassword = options.getKeyStorePassword();
            char[] keyStorePasswordChars = keyStorePassword != null ? keyStorePassword.toCharArray() : null;
            loadKeyStore();
            X509Certificate certificate = generateSelfSignedCertificate(keyPair);
            keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyStorePasswordChars, new X509Certificate[]{certificate});
        } else {
            // Save both private key only for non-PKCS#11 providers
            if (options.getPrivateKeyFile() != null) {
                File keyFile = getPrivateFile(keyName);
                PrivateKey privateKey = keyPair.getPrivate();
                if (privateKey == null) {
                    throw new IOException("Private key is null, cannot save to file");
                }
                options.writeData(keyFile, privateKey.getEncoded());
            }
        }
        return publicKeyEncodedData;
    }

    private File getPrivateFile(String keyName) {
        File basePrivateKeyFile = options.getPrivateKeyFile();
        File keyFile;
        if (keyName != null) {
            // Create a new file name based on the base file path and the key name
            String baseFileName = basePrivateKeyFile.getName();
            String baseFilePath = basePrivateKeyFile.getParent();
            String newFileName = baseFileName + "-" + keyName;
            if (baseFilePath != null) {
                keyFile = new File(baseFilePath, newFileName);
            } else {
                keyFile = new File(newFileName);
            }
        } else {
            keyFile = basePrivateKeyFile;
        }
        return keyFile;
    }
}
