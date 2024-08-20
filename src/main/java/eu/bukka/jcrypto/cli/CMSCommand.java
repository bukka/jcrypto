package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.cms.CMSEnvelope;
import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "cms", mixinStandardHelpOptions = true,
        description = "Processing RFC 3852 Cryptographic Message Syntax (CMS).")
public class CMSCommand extends CommonCommand implements Callable<Integer>, CMSEnvelopeOptions {
    @Parameters(index = "0", description = "Mode")
    private String mode;

    @Option(names = {"-c", "--cipher"}, description = "Cipher to use")
    private String algorithm = "aes-256-cbc";

    @Option(names = {"--secret-key"}, description = "Secret key for KEK recipient type")
    private String secretKey;

    @Option(names = {"--secret-key-id"}, description = "Secret key for KEK recipient type")
    private String secretKeyIdentifier;

    @Option(names = {"--cert"}, description = "Certificate for KeyTrans recipient type")
    private File certificateFile;

    @Option(names = {"--private-key"}, description = "Private key for KeyTrans recipient type")
    private File privateKeyFile;

    public String getAlgorithm() {
        return algorithm;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public String getSecretKeyIdentifier() {
        return secretKeyIdentifier;
    }

    public File getCertificateFile() {
        return certificateFile;
    }

    public File getPrivateKeyFile() {
        return privateKeyFile;
    }

    @Override
    public Integer call() throws Exception {
        switch (mode) {
            case "encrypt":
                new CMSEnvelope(this).encrypt();
                break;
            case "decrypt":
                new CMSEnvelope(this).decrypt();
                break;
            default:
                throw new Exception("Unknown CMS mode: " + mode);
        }

        return 0;
    }
}
