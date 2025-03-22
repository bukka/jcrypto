package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class RecipientData {
    X509Certificate certificate;

    X509Certificate recipientCertificate;

    X509Certificate senderCertificate;

    protected CMSEnvelopeOptions options;

    protected static class Algorithm {
        private final ASN1ObjectIdentifier identifier;
        private final boolean authenticated;

        public Algorithm(ASN1ObjectIdentifier identifier, boolean authenticate) {
            this.identifier = identifier;
            this.authenticated = authenticate;
        }

        public Algorithm(ASN1ObjectIdentifier identifier) {
            this.identifier = identifier;
            this.authenticated = false;
        }

        public boolean isAuthenticated() {
            return authenticated;
        }

        public ASN1ObjectIdentifier getIdentifier() {
            return identifier;
        }
    }

    protected Algorithm getAlgorithm(String algorithm) {
        switch (algorithm) {
            case "AES128_GCM":
            case "AES-128-GCM":
                return new Algorithm(CMSAlgorithm.AES128_GCM, true);
            case "AES256_GCM":
            case "AES-256-GCM":
                return new Algorithm(CMSAlgorithm.AES256_GCM, true);
            case "AES128_CBC":
            case "AES-128-CBC":
                return new Algorithm(CMSAlgorithm.AES128_CBC);
            case "AES256_CBC":
            case "AES-256-CBC":
                return new Algorithm(CMSAlgorithm.AES256_CBC);
            default:
                throw new InvalidParameterException("Invalid algorithm " + algorithm);
        }
    }

    protected Algorithm getKeyAlgorithm() {
        String keyAlgorithm = options.getKeyAlgorithm();
        if (keyAlgorithm == null) {
            keyAlgorithm = options.getAlgorithm();
        }
        return getAlgorithm(keyAlgorithm.toUpperCase());
    }

    public RecipientData(CMSEnvelopeOptions options) {
        this.options = options;
    }

    protected byte[] getSecretKeyId() {
        return Strings.toByteArray(options.getSecretKeyIdentifier());
    }

    protected SecretKey getSecretKey() {
        return new SecretKeySpec(Hex.decode(options.getSecretKey()), "AES");
    }

    protected X509Certificate loadCertificate(File certificateFile) throws CMSException {
        try (FileReader certReader = new FileReader(certificateFile);
             PEMParser pemParser = new PEMParser(certReader)) {

            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate((X509CertificateHolder) object);
            } else if (object instanceof Certificate) {
                return (X509Certificate) object;
            } else {
                throw new CMSException("Invalid certificate format");
            }
        } catch (IOException e) {
            throw new CMSException("Failed to load certificate", e);
        } catch (CertificateException e) {
            throw new CMSException("Failed to parse certificate", e);
        }
    }

    protected X509Certificate getCertificate() throws CMSException {
        if (certificate == null) {
            certificate = loadCertificate(options.getCertificateFile());
        }
        return certificate;
    }

    protected X509Certificate getRecipientCertificate() throws CMSException {
        if (recipientCertificate == null) {
            recipientCertificate = loadCertificate(options.getRecipientCertificateFile());
        }
        return recipientCertificate;
    }

    protected X509Certificate getSenderCertificate() throws CMSException {
        if (senderCertificate == null) {
            senderCertificate = loadCertificate(options.getSenderCertificateFile());
        }
        return senderCertificate;
    }

    protected PrivateKey getPrivateKey() throws CMSException {
        try (FileReader keyReader = new FileReader(options.getPrivateKeyFile());
             PEMParser pemParser = new PEMParser(keyReader)) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                // TODO: handle a decryption password if the key is encrypted.
                PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(null); // pass decryption password
                return converter.getPrivateKey(privateKeyInfo);
            } else if (object instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) object);
            } else if (object instanceof PEMKeyPair) {
                KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
                return kp.getPrivate();
            } else {
                throw new CMSException("Invalid private key format");
            }
        } catch (IOException e) {
            throw new CMSException("Failed to load private key", e);
        } catch (PKCSException e) {
            throw new RuntimeException(e);
        }
    }

    protected boolean isCertificateForKeyAgree() throws CMSException {
        certificate = getCertificate();
        PublicKey publicKey = getCertificate().getPublicKey();
        String algorithm = publicKey.getAlgorithm();
        return algorithm.equalsIgnoreCase("DH") || algorithm.equalsIgnoreCase("EC");
    }
}
