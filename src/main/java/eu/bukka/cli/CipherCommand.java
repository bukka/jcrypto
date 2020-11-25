package eu.bukka.cli;

import eu.bukka.cipher.CipherEnvelope;
import eu.bukka.options.CipherOptions;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.concurrent.Callable;

@Command(name = "cipher", mixinStandardHelpOptions = true,
        description = "Block and Stream ciphers.")
public class CipherCommand extends CommonCommand implements Callable<Integer>, CipherOptions {
    @Parameters(index = "0", description = "Action")
    private String action;

    @Option(names = {"-a", "--algorithm"}, description = "Cipher algorithm to use")
    private String algorithm = "aes-256-cbc";

    @Option(names = {"-K", "--key"}, description = "Raw key, in hex")
    private String key;

    @Option(names = {"--padding"}, description = "Padding to use if any")
    private String padding;

    @Option(names = {"--iv"}, description = "IV in hex")
    private String iv;

    public String getAlgorithm() {
        return algorithm;
    }

    public String getKey() {
        return key;
    }

    public String getIv() {
        return iv;
    }

    public String getPadding() {
        return padding;
    }

    @Override
    public Integer call() throws Exception {
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
