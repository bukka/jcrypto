package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.IOException;
import java.security.*;
import javax.crypto.KeyAgreement;

public class KeyAgreementEnvelope extends PKeyEnvelope {

    private KeyAgreement keyAgreement;

    public KeyAgreementEnvelope(PKeyOptions options) {
        super(options);
    }

    private KeyAgreement getKeyAgreement() throws NoSuchAlgorithmException {
        if (keyAgreement == null) {
            Provider provider = options.getProvider();
            if (provider == null) {
                keyAgreement = KeyAgreement.getInstance(options.getAlgorithm());
            } else {
                keyAgreement = KeyAgreement.getInstance(options.getAlgorithm(), provider);
            }
        }
        return keyAgreement;
    }

    /**
     * Derive shared secret.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void derive() throws GeneralSecurityException, IOException {
        // Initialize KeyAgreement with the private key
        PrivateKey privateKey = getPrivateKey();
        KeyAgreement keyAgreement = getKeyAgreement();
        keyAgreement.init(privateKey);

        // Load peer's public key
        PublicKey peerPublicKey = getPublicKey();
        keyAgreement.doPhase(peerPublicKey, true);

        // Generate shared secret
        byte[] sharedSecret = keyAgreement.generateSecret();

        // Output the shared secret
        options.writeOutputData(sharedSecret);
    }
}