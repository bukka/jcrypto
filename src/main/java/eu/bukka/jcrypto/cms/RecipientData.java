package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
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
        // Hex-decoded to match OpenSSL, which runs -secretkeyid through OPENSSL_hexstr2buf.
        return Hex.decode(options.getSecretKeyIdentifier());
    }

    protected SecretKey getSecretKey() {
        return new SecretKeySpec(Hex.decode(options.getSecretKey()), "AES");
    }

    protected X509Certificate loadCertificate(File certificateFile) throws CMSException {
        return PemLoader.loadCertificate(certificateFile);
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
        return PemLoader.loadPrivateKey(options.getPrivateKeyFile());
    }

    protected boolean isCertificateForKeyAgree() throws CMSException {
        certificate = getCertificate();
        PublicKey publicKey = getCertificate().getPublicKey();
        String algorithm = publicKey.getAlgorithm();
        return algorithm.equalsIgnoreCase("DH") || algorithm.equalsIgnoreCase("EC");
    }
}
