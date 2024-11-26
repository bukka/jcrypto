package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class KeyGeneratorEnvelope extends PKeyEnvelope {

    public KeyGeneratorEnvelope(PKeyOptions options) {
        super(options);
    }

    public void generate() throws GeneralSecurityException, IOException {
        KeyPair keyPair = generateKeyPair();
        saveKeyPair(keyPair);
    }

    private KeyPair generateKeyPair() throws GeneralSecurityException {
        String algorithm = options.getAlgorithm();
        String parameters = options.getParameters();

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);

        if ("EC".equalsIgnoreCase(algorithm) && parameters != null) {
            // Specific curve name for EC
            ECGenParameterSpec ecSpec = new ECGenParameterSpec(parameters);
            keyPairGenerator.initialize(ecSpec);
        } else if (parameters != null) {
            // Generic key size for other algorithms (e.g., RSA)
            int keySize = Integer.parseInt(parameters);
            keyPairGenerator.initialize(keySize);
        }

        return keyPairGenerator.generateKeyPair();
    }

    private void saveKeyPair(KeyPair keyPair) throws IOException {
        if (options.getPrivateKeyFile() != null) {
            saveKeyToFile(keyPair.getPrivate(), options.getPrivateKeyFile());
        }
        if (options.getPublicKeyFile() != null) {
            saveKeyToFile(keyPair.getPublic(), options.getPublicKeyFile());
        }
    }

    private void saveKeyToFile(Key key, File file) throws IOException {
        options.writeData(file, key.getEncoded());
    }
}
