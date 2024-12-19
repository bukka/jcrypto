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
    private byte[] derive(PublicKey peerPublicKey) throws GeneralSecurityException, IOException {
        // Initialize KeyAgreement with the private key
        PrivateKey privateKey = getPrivateKey();
        KeyAgreement keyAgreement = getKeyAgreement();
        keyAgreement.init(privateKey);

        // Load peer's public key
        keyAgreement.doPhase(peerPublicKey, true);

        // Generate and returns shared secret
        return keyAgreement.generateSecret();
    }

    /**
     * Derive shared secret.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public void derive() throws GeneralSecurityException, IOException {
        options.writeOutputData(derive(getPublicKey()));
    }

    /**
     * Derive shared secret.
     *
     * @throws GeneralSecurityException
     * @throws IOException
     */
    public byte[] derive(byte[] pubKeyBytes) throws GeneralSecurityException, IOException {
        return derive(getPublicKeyFromBytes(pubKeyBytes));
    }
}