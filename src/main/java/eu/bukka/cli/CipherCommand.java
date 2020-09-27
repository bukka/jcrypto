package eu.bukka.cli;

import eu.bukka.cipher.CipherEnvelope;
import eu.bukka.cms.CMSEnvelope;
import eu.bukka.options.CipherOptions;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "cipher", mixinStandardHelpOptions = true,
        description = "Block and Stream ciphers.")
public class CipherCommand implements Callable<Integer>, CipherOptions {
    @Parameters(index = "0", description = "Action")
    private String action;

    @Option(names = {"-i", "--in"}, description = "Input file", required = true)
    private File inputFile;

    @Option(names = {"-o", "--out"}, description = "Output file")
    private File outputFile;

    @Option(names = {"-f", "--form"}, description = "Input and output form")
    private String form = "PEM";

    @Option(names = {"-a", "--algorithm"}, description = "Cipher algorithm to use")
    private String algorithm = "aes-256-cbc";

    @Option(names = {"-k", "--key"}, description = "Raw key, in hex")
    private String key;

    @Option(names = {"--iv"}, description = "IV in hex")
    private String iv;

    public File getInputFile() {
        return inputFile;
    }

    public File getOutputFile() {
        return outputFile;
    }

    public String getForm() {
        return form;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public String getKey() {
        return key;
    }

    public String getIv() {
        return iv;
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
