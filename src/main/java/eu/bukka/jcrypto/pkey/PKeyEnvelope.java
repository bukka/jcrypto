package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.IOException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class PKeyEnvelope {
    protected PKeyOptions options;

    protected KeyStore keyStore;

    public PKeyEnvelope(PKeyOptions options) {
        this.options = options;
    }

    protected void loadKeyStore() throws GeneralSecurityException, IOException {
        if (keyStore == null) {
            String keyStorePassword = options.getKeyStorePassword();
            keyStore = KeyStore.getInstance(options.getKeyStoreName());
            keyStore.load(null, keyStorePassword != null ? keyStorePassword.toCharArray() : null);
        }
    }

    protected KeyStore getKeyStore() throws GeneralSecurityException, IOException {
        if (keyStore == null) {
            loadKeyStore();
        }
        return keyStore;
    }

    private KeyFactory getKeyFactory(String algorithm) throws NoSuchAlgorithmException {
        if (algorithm.toUpperCase().contains("EC")) {
            return KeyFactory.getInstance("EC");
        } else if (algorithm.toUpperCase().contains("RSA")) {
            return KeyFactory.getInstance("RSA");
        } else if (algorithm.toUpperCase().contains("DSA")) {
            return KeyFactory.getInstance("DSA");
        } else {
            return KeyFactory.getInstance(algorithm);
        }
    }

    protected PublicKey getPublicKey() throws GeneralSecurityException, IOException {
        if (options.getPublicKeyFile() == null) {
            String alias = options.getPublicKeyAlias();
            if (alias == null) {
                throw new SecurityException("No alias or file for public key");
            }
            return getPublicKeyFromKeyStore(alias);
        } else {
            return getPublicKeyFromFile();
        }
    }

    private PublicKey getPublicKeyFromFile() throws IOException, GeneralSecurityException {
        byte[] publicKeyBytes = options.getPublicKeyFileData();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = getKeyFactory(options.getAlgorithm());
        return keyFactory.generatePublic(keySpec);
    }

    private PublicKey getPublicKeyFromKeyStore(String publicKeyAlias) throws GeneralSecurityException, IOException {
        KeyStore keyStore = getKeyStore();
        return keyStore.getCertificate(publicKeyAlias).getPublicKey();
    }

    protected PrivateKey getPrivateKey() throws GeneralSecurityException, IOException {
        if (options.getPrivateKeyFile() == null) {
            String alias = options.getPrivateKeyAlias();
            if (alias == null) {
                throw new SecurityException("No alias or file for private key");
            }
            return getPrivateKeyFromKeyStore(alias);
        } else {
            return getPrivateKeyFromFile();
        }
    }

    private PrivateKey getPrivateKeyFromFile() throws IOException, GeneralSecurityException {
        byte[] privateKeyBytes = options.getPrivateKeyFileData();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = getKeyFactory(options.getAlgorithm());
        return keyFactory.generatePrivate(keySpec);
    }

    private PrivateKey getPrivateKeyFromKeyStore(String publicKeyAlias) throws GeneralSecurityException, IOException {
        KeyStore keyStore = getKeyStore();
        return (PrivateKey) keyStore.getKey(publicKeyAlias, options.getKeyStorePassword().toCharArray());
    }
}
