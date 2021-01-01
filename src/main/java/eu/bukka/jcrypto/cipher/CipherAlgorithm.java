package eu.bukka.jcrypto.cipher;

import eu.bukka.jcrypto.options.CipherOptions;

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
        this.padding = padding != null ? padding : "PKCS5Padding";
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
        String padding = options.getPadding();
        String mode;
        String cipher = "AES";
        int keySize = 256;
        switch (algorithm) {
            case "AES128_CCM":
            case "AES-128-CCM":
                keySize = 128;
            case "AES256_CCM":
            case "AES-256-CCM":
                mode = "CCM";
                break;
            case "AES128_GCM":
            case "AES-128-GCM":
                keySize = 128;
            case "AES256_GCM":
            case "AES-256-GCM":
                mode = "GCM";
                break;
            case "AES128_CBC":
            case "AES-128-CBC":
                keySize = 128;
            case "AES256_CBC":
            case "AES-256-CBC":
                mode = "CBC";
                break;
            case "AES128_CRT":
            case "AES-128-CRT":
                keySize = 128;
            case "AES256_CRT":
            case "AES-256-CRT":
                mode = "CRT";
                break;
            case "AES128_ECB":
            case "AES-128-ECB":
                keySize = 128;
            case "AES256_ECB":
            case "AES-256-ECB":
                mode = "ECB";
                break;
            default:
                throw new InvalidParameterException("Invalid algorithm " + algorithm);
        }

        return new CipherAlgorithm(cipher, mode, padding, keySize);
    }

    public String getCipher() {
        return cipher;
    }

    public int getKeySize() {
        return keySize;
    }

    public boolean hasIv() {
        return !mode.equals("ECB");
    }

    public String transform() {
        return String.format("%s/%s/%s", cipher, mode, padding);
    }
}
