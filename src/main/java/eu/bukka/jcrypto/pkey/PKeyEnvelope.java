package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PKeyEnvelope {
    protected PKeyOptions options;

    private KeyStore keyStore;

    public PKeyEnvelope(PKeyOptions options) {
        this.options = options;
    }

    private KeyStore getKeyStore() throws KeyStoreException {
        if (keyStore == null) {
            keyStore = KeyStore.getInstance(options.getKeyStoreName());
        }
        return keyStore;
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
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBytes);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(options.getAlgorithm()); // or "DSA", "EC" depending on your key type
        return keyFactory.generatePublic(keySpec);
    }

    private PublicKey getPublicKeyFromKeyStore(String publicKeyAlias) throws KeyStoreException {
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
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBytes);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(options.getAlgorithm()); // or "DSA", "EC" depending on your key type
        return keyFactory.generatePrivate(keySpec);
    }

    private PrivateKey getPrivateKeyFromKeyStore(String publicKeyAlias) throws GeneralSecurityException {
        KeyStore keyStore = getKeyStore();
        return (PrivateKey) keyStore.getKey(publicKeyAlias, options.getKeyStorePassword().toCharArray());
    }
}
