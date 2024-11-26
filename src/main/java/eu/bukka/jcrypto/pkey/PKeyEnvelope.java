package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(options.getAlgorithm());
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
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(options.getAlgorithm());
        return keyFactory.generatePrivate(keySpec);
    }

    private PrivateKey getPrivateKeyFromKeyStore(String publicKeyAlias) throws GeneralSecurityException {
        KeyStore keyStore = getKeyStore();
        return (PrivateKey) keyStore.getKey(publicKeyAlias, options.getKeyStorePassword().toCharArray());
    }
}
