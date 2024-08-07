package eu.bukka.jcrypto.cipher;

import eu.bukka.jcrypto.options.CipherOptions;

import java.security.InvalidParameterException;
import java.util.Arrays;
import java.util.Objects;

public class CipherAlgorithm {
    final private String[] STREAM_MODES = {"CTR", "OFB", "CFB"};

    /**
     * The cipher name (e.g. AES)
     */
    private final String cipher;

    /**
     * Streaming block mode
     */
    private final String mode;

    /**
     * Cipher padding (e.g. NoPadding or PKCS5Padding)
     */
    private final String padding;

    /**
     * The key size or 0 if unspecified (taken from the key length)
     */
    private final int keySize;

    public CipherAlgorithm(String cipher, String mode, String padding, int keySize) {
        this.cipher = cipher;
        this.mode = mode;
        this.keySize = keySize;
        this.padding = padding != null ? padding : "NoPadding";
        if (isStreamMode() && !Objects.equals(this.padding, "NoPadding")) {
            throw new InvalidParameterException("Padding cannot be used for stream mode");
        }
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
        String algorithm = options.getAlgorithm();
        if (algorithm == null || algorithm.isEmpty()) {
            throw new InvalidParameterException("Algorithm cannot be an empty string");
        }
        String padding = options.getPadding();
        String mode = null;
        String cipher = "AES";
        int keySize = 256;
        switch (algorithm.toUpperCase()) {
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
            case "AES128_CTR":
            case "AES-128-CTR":
                keySize = 128;
            case "AES256_CTR":
            case "AES-256-CTR":
                mode = "CTR";
                break;
            case "AES128_CFB":
            case "AES-128-CFB":
                keySize = 128;
            case "AES256_CFB":
            case "AES-256-CFB":
                mode = "CFB";
                break;
            case "AES128_OFB":
            case "AES-128-OFB":
                keySize = 128;
            case "AES256_OFB":
            case "AES-256-OFB":
                mode = "OFB";
                break;
            case "AES128_ECB":
            case "AES-128-ECB":
                keySize = 128;
            case "AES256_ECB":
            case "AES-256-ECB":
                mode = "ECB";
                break;
            default:
                // try BC based format
                keySize = 0;
                String[] parts = algorithm.split("/");
                if (parts.length > 3) {
                    throw new InvalidParameterException("Invalid algorithm " + algorithm);
                }
                if (parts.length > 2) {
                    padding = parts[2];
                }
                if (parts.length > 1) {
                    mode = parts[1];
                }
                cipher = parts[0];
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

    public boolean isStreamMode() {
        return Arrays.asList(STREAM_MODES).contains(mode);
    }

    public String transform() {
        return mode == null ? cipher : String.format("%s/%s/%s", cipher, mode, padding);
    }
}
