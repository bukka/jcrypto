package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.cipher.CipherEnvelope;
import eu.bukka.jcrypto.options.CipherOptions;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "cipher", mixinStandardHelpOptions = true, showDefaultValues = true, usageHelpWidth = 100,
        description = "Raw AES block and stream cipher encryption/decryption (operates on raw bytes).",
        footer = {
                "",
                "Examples:",
                "  Encrypt (CBC, hex key and IV):",
                "    jcrypto cipher encrypt -a aes-128-cbc -K 2b7e151628aed2a6abf7158809cf4f3c \\",
                "      --iv 000102030405060708090a0b0c0d0e0f -i in.bin -o out.bin",
                "  Decrypt:",
                "    jcrypto cipher decrypt -a aes-128-cbc -K 2b7e151628aed2a6abf7158809cf4f3c \\",
                "      --iv 000102030405060708090a0b0c0d0e0f -i out.bin -o dec.bin",
                "  Encrypt (GCM, write the generated IV out):",
                "    jcrypto cipher encrypt -a aes-128-gcm -K 2b7e151628aed2a6abf7158809cf4f3c \\",
                "      -i in.bin -o out.bin --iv-out iv.bin"
        })
public class CipherCommand extends CommonCommand implements Callable<Integer>, CipherOptions {
    @Parameters(index = "0", paramLabel = "<action>", description = "Operation: encrypt or decrypt")
    private String action;

    @Option(names = {"-a", "--algorithm"},
            description = "AES cipher as name-keysize-mode (e.g. aes-128-cbc, aes-256-gcm, aes-128-ctr) "
                    + "or name/mode/padding. Modes: CBC, CTR, GCM, CCM, CFB, OFB, ECB.")
    private String algorithm = "aes-256-cbc";

    @Option(names = {"-K", "--key"}, description = "Raw key, in hex")
    private String key;

    @Option(names = {"--padding"},
            description = "Padding for block modes, e.g. PKCS5Padding or NoPadding")
    private String padding;

    @Option(names = {"--iv"},
            description = "IV, in hex (required to decrypt modes that use an IV)")
    private String iv;

    @Option(names = {"--iv-out"}, description = "File to write the generated IV to (encrypt)")
    private File ivOutputFile;

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getKey() {
        return key;
    }

    @Override
    public String getIv() {
        return iv;
    }

    @Override
    public File getIvOutputFile() {
        return ivOutputFile;
    }

    @Override
    public String getPadding() {
        return padding;
    }

    @Override
    public Integer call() throws Exception {
        addSecurityProviders();
        switch (action) {
            case "encrypt":
                new CipherEnvelope(this).encrypt();
                break;
            case "decrypt":
                new CipherEnvelope(this).decrypt();
                break;
            default:
                throw new Exception("Unknown cipher action: " + action);
        }

        return 0;
    }
}
