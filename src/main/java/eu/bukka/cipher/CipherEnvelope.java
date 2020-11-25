package eu.bukka.cipher;

import eu.bukka.options.CipherOptions;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class CipherEnvelope {
    protected CipherOptions options;

    public CipherEnvelope(CipherOptions options) {
        this.options = options;
    }

    public void encrypt() throws IOException, GeneralSecurityException {
        CipherAlgorithm algorithm = CipherAlgorithm.fromOptions(options);
        Cipher cipher = Cipher.getInstance(algorithm.transform(), "BC");

        byte[] keyBytes = Hex.decode(options.getKey());
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        cipher.init(Cipher.ENCRYPT_MODE, key);
        options.writeOutputData(cipher.doFinal(options.getInputData()));
    }

    public void decrypt() throws IOException {

    }
}
