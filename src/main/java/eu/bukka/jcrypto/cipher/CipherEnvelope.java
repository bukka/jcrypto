package eu.bukka.jcrypto.cipher;

import eu.bukka.jcrypto.options.CipherOptions;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;

public class CipherEnvelope {
    protected CipherOptions options;

    public CipherEnvelope(CipherOptions options) {
        this.options = options;
    }

    private void crypt(int opmode) throws IOException, GeneralSecurityException {
        CipherAlgorithm algorithm = CipherAlgorithm.fromOptions(options);
        Cipher cipher = Cipher.getInstance(algorithm.transform(), "BC");

        byte[] keyBytes = Hex.decode(options.getKey());
        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        if (algorithm.hasIv()) {
            if (options.getIv() == null) {
                if (opmode == Cipher.DECRYPT_MODE) {
                    throw new InvalidParameterException("Decryption algorithm requires IV");
                }
                cipher.init(opmode, key);
            } else {
                cipher.init(opmode, key, new IvParameterSpec(Hex.decode(options.getIv())));
            }
        } else {
            cipher.init(opmode, key);
        }
        options.writeOutputData(cipher.doFinal(options.getInputData()));
        if (options.getIvOutputFile() != null) {
            options.writeData(options.getIvOutputFile(), cipher.getIV());
        }
    }

    public void encrypt() throws IOException, GeneralSecurityException {
        crypt(Cipher.ENCRYPT_MODE);
    }

    public void decrypt() throws IOException, GeneralSecurityException {
        crypt(Cipher.DECRYPT_MODE);
    }
}
