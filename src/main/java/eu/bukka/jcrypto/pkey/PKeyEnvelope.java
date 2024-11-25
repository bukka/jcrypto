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

    protected PublicKey getPublicKey() throws Exception {
        File publicKeyFile = options.getPublicKeyFile();
        if (publicKeyFile == null) {
            String alias = options.getPublicKeyAlias();
            if (alias == null) {
                throw new Exception("No alias or file for public key");
            }
            return getPublicKeyFromKeyStore(alias);
        } else {
            return getPublicKeyFromFile(publicKeyFile);
        }
    }

    private PublicKey getPublicKeyFromFile(File publicKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyBytes);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(options.getAlgorithm()); // or "DSA", "EC" depending on your key type
        return keyFactory.generatePublic(keySpec);
    }

    private PublicKey getPublicKeyFromKeyStore(String publicKeyAlias) throws KeyStoreException {
        KeyStore keyStore = getKeyStore();
        return keyStore.getCertificate(publicKeyAlias).getPublicKey();
    }

    protected PrivateKey getPrivateKey() throws Exception {
        File privateKeyFile = options.getPrivateKeyFile();
        if (privateKeyFile == null) {
            String alias = options.getPrivateKeyAlias();
            if (alias == null) {
                throw new Exception("No alias or file for private key");
            }
            return getPrivateKeyFromKeyStore(alias);
        } else {
            return getPrivateKeyFromFile(privateKeyFile);
        }
    }

    private PrivateKey getPrivateKeyFromFile(File privateKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyBytes);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(options.getAlgorithm()); // or "DSA", "EC" depending on your key type
        return keyFactory.generatePrivate(keySpec);
    }

    private PrivateKey getPrivateKeyFromKeyStore(String publicKeyAlias) throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException {
        KeyStore keyStore = getKeyStore();
        return (PrivateKey) keyStore.getKey(null, options.getKeyStorePassword().toCharArray());
    }
}
