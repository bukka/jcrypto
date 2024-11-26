package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.IOException;
import java.security.*;

public class SignatureEnvelope extends PKeyEnvelope {
    Signature signature;

    public SignatureEnvelope(PKeyOptions options) {
        super(options);
    }

    private Signature getSignature() throws NoSuchAlgorithmException, NoSuchProviderException {
        if (signature == null) {
            Provider provider = options.getProvider();
            if (provider == null) {
                signature = Signature.getInstance(options.getAlgorithm());
            } else {
                signature = Signature.getInstance(options.getAlgorithm(), provider);
            }
        }
        return signature;
    }

    public void sign() throws GeneralSecurityException, IOException {
        Signature sig = getSignature();
        sig.initSign(getPrivateKey());
        sig.update(options.getInputData());
        options.writeOutputData(sig.sign());
    }

    public void verify() throws GeneralSecurityException, IOException  {
        Signature sig = getSignature();
        sig.initVerify(getPublicKey());
        sig.update(options.getInputData());
        if (!sig.verify(options.getSignatureFileData())) {
            throw new SecurityException("Signature verification failed");
        }
    }
}
