package eu.bukka.jcrypto.cms;

import java.security.InvalidParameterException;
import java.security.PrivateKey;

/**
 * CMS SignedData signature algorithm: a digest choice combined with a signing key yields the JCA
 * signature algorithm name (for example "SHA256withRSA" or "Ed25519").
 */
public class SignatureAlgorithm {
    private final String digest;

    private SignatureAlgorithm(String digest) {
        this.digest = digest;
    }

    public static SignatureAlgorithm fromDigest(String digest) {
        if (digest == null) {
            return new SignatureAlgorithm("SHA256");
        }
        switch (digest.toUpperCase().replace("-", "").replace("_", "")) {
            case "SHA1":
                return new SignatureAlgorithm("SHA1");
            case "SHA224":
                return new SignatureAlgorithm("SHA224");
            case "SHA256":
                return new SignatureAlgorithm("SHA256");
            case "SHA384":
                return new SignatureAlgorithm("SHA384");
            case "SHA512":
                return new SignatureAlgorithm("SHA512");
            default:
                throw new InvalidParameterException("Invalid digest algorithm " + digest);
        }
    }

    /**
     * JCA signature algorithm name for signing with the given key. Edwards-curve keys carry their own
     * digest, so the configured digest is ignored for them.
     */
    public String getName(PrivateKey privateKey) {
        String keyAlgorithm = privateKey.getAlgorithm().toUpperCase();
        if (keyAlgorithm.contains("25519")) {
            return "Ed25519";
        }
        if (keyAlgorithm.contains("448")) {
            return "Ed448";
        }
        if (keyAlgorithm.startsWith("ED")) {
            return "Ed25519";
        }
        return digest + "with" + getKeyName(keyAlgorithm);
    }

    private String getKeyName(String keyAlgorithm) {
        if (keyAlgorithm.contains("RSA")) {
            return "RSA";
        }
        if (keyAlgorithm.equals("EC") || keyAlgorithm.contains("ECDSA")) {
            return "ECDSA";
        }
        if (keyAlgorithm.contains("DSA")) {
            return "DSA";
        }
        throw new InvalidParameterException("Unsupported signing key algorithm " + keyAlgorithm);
    }
}
