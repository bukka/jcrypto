package eu.bukka.cli;

import eu.bukka.service.CMSEncryptor;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.nio.file.Files;
import java.util.concurrent.Callable;

@Command(name = "cms", mixinStandardHelpOptions = true,
        description = "Processing RFC 3852 Cryptographic Message Syntax (CMS).")
public class CMSCommand implements Callable<Integer> {
    @Parameters(index = "0", description = "Mode")
    private String mode;

    @Option(names = {"-i", "--in"}, description = "Input file", required = true)
    private File in;

    @Option(names = {"-o", "--out"}, description = "Output file")
    private File out;

    @Option(names = {"-f", "--form"}, description = "Input and output form")
    private String form;

    @Option(names = {"-c", "--cipher"}, description = "Cipher to use")
    private String algorithm = "aes-256-cbc";

    @Override
    public Integer call() throws Exception {
        byte[] fileContents = Files.readAllBytes(in.toPath());
        switch (mode) {
            case "encyrpt":
                CMSEncryptor encryptor = new CMSEncryptor();
                break;
            default:
                throw new Exception("Unknown CMS mode: " + mode);
        }

        return 0;
    }
}
