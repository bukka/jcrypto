package eu.bukka.cli;

import eu.bukka.cms.CMSEnvelope;
import eu.bukka.cms.options.CMSEnvelopedDataOptions;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "cms", mixinStandardHelpOptions = true,
        description = "Processing RFC 3852 Cryptographic Message Syntax (CMS).")
public class CMSCommand implements Callable<Integer>, CMSEnvelopedDataOptions {
    @Parameters(index = "0", description = "Mode")
    private String mode;

    @Option(names = {"-i", "--in"}, description = "Input file", required = true)
    private File inputFile;

    @Option(names = {"-o", "--out"}, description = "Output file")
    private File outputFile;

    @Option(names = {"-f", "--form"}, description = "Input and output form")
    private String form;

    @Option(names = {"-c", "--cipher"}, description = "Cipher to use")
    private String algorithm = "aes-256-cbc";

    @Option(names = {"--secret-key"}, description = "Secret key for KEK recipient type")
    private String secretKey;

    @Option(names = {"--secret-key-id"}, description = "Secret key for KEK recipient type")
    private String secretKeyIdentifier;

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

    public String getSecretKey() {
        return secretKey;
    }

    public String getSecretKeyIdentifier() {
        return secretKeyIdentifier;
    }

    @Override
    public Integer call() throws Exception {
        switch (mode) {
            case "encrypt":
                new CMSEnvelope(this).encrypt();
                break;
            default:
                throw new Exception("Unknown CMS mode: " + mode);
        }

        return 0;
    }
}
