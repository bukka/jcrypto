package eu.bukka.cipher;

import eu.bukka.options.CipherOptions;

import java.security.InvalidParameterException;

public class CipherAlgorithm {
    private String cipher;

    private String mode;

    private String padding;

    private int keySize;

    public CipherAlgorithm(String cipher, String mode, String padding, int keySize) {
        this.cipher = cipher;
        this.mode = mode;
        this.keySize = keySize;
        this.padding = padding;
    }

    public CipherAlgorithm(String cipher, String mode) {
        this(cipher, mode, "NoPadding", 0);
    }

    public CipherAlgorithm(String mode, int keySize) {
        this("AES", mode, "NoPadding", keySize);
    }

    public CipherAlgorithm(String mode) {
        this(mode, 256);
    }

    public static CipherAlgorithm fromOptions(CipherOptions options) {
        String algorithm = options.getAlgorithm().toUpperCase();
        switch (algorithm) {
            case "AES128_CCM":
            case "AES-128-CCM":
                return new CipherAlgorithm("CCM", 128);
            case "AES256_CCM":
            case "AES-258-CCM":
                return new CipherAlgorithm("CCM");
            case "AES128_GCM":
            case "AES-128-GCM":
                return new CipherAlgorithm("GCM", 128);
            case "AES256_GCM":
            case "AES-256-GCM":
                return new CipherAlgorithm("GCM");
            case "AES128_CBC":
            case "AES-128-CBC":
                return new CipherAlgorithm("CBC", 128);
            case "AES256_CBC":
            case "AES-258-CBC":
                return new CipherAlgorithm("CBC");
            case "AES128_CRT":
            case "AES-128-CRT":
                return new CipherAlgorithm("CRT", 128);
            case "AES256_CRT":
            case "AES-258-CRT":
                return new CipherAlgorithm("CRT");
            case "AES128_ECB":
            case "AES-128-ECB":
                return new CipherAlgorithm("ECB", 128);
            case "AES256_ECB":
            case "AES-256-ECB":
                return new CipherAlgorithm("ECB");
            default:
                throw new InvalidParameterException("Invalid algorithm " + algorithm);
        }
    }

    public String getCipher() {
        return cipher;
    }

    public boolean hasIv() {
        return !mode.equals("ECB");
    }

    public String transform() {
        return String.format("%s/%s/%s", cipher, mode, padding);
    }
}
