package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class SignatureEnvelope extends PKeyEnvelope {
    Signature signature;

    public SignatureEnvelope(PKeyOptions options) {
        super(options);
    }

    private Signature getSignature() throws NoSuchAlgorithmException {
        if (signature == null) {
            signature = Signature.getInstance(options.getAlgorithm());
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
