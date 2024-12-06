package eu.bukka.jcrypto.pkey;

import eu.bukka.jcrypto.options.PKeyOptions;

import java.io.IOException;
import java.security.*;

public class SignatureEnvelope extends PKeyEnvelope {
    Signature signature;

    public SignatureEnvelope(PKeyOptions options) {
        super(options);
    }

    private Signature getSignature() throws NoSuchAlgorithmException {
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

    public byte[] sign(byte[] data) throws GeneralSecurityException, IOException {
        Signature sig = getSignature();
        sig.initSign(getPrivateKey());
        sig.update(data);
        return sig.sign();
    }

    public void sign() throws GeneralSecurityException, IOException {
        options.writeOutputData(sign(options.getInputData()));
    }

    public boolean verify(byte[] data, byte[] signature) throws GeneralSecurityException, IOException  {
        Signature sig = getSignature();
        sig.initVerify(getPublicKey());
        sig.update(data);
        return sig.verify(signature);
    }

    public void verify() throws GeneralSecurityException, IOException  {
        if (!verify(options.getInputData(), options.getSignatureFileData())) {
            throw new SecurityException("Signature verification failed");
        }
    }
}
