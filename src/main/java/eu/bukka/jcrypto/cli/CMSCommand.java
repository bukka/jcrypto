package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.cms.CMSEnvelope;
import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import picocli.CommandLine;
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

    @CommandLine.Option(names = {"--sender-cert"}, description = "Sender certificate for KeyAgree recipient type")
    private File senderCertificateFile;

    @CommandLine.Option(names = {"--recipient-cert"}, description = "Recipient certificate for KeyAgree recipient type")
    private File recipientCertificateFile;

    @CommandLine.Option(names = {"--private-key"}, description = "Private key for KeyTrans recipient type")
    private File privateKeyFile;

    @CommandLine.Option(names = {"--public-key"},
            description = "Public key for KeyAgree recipient type (alternative to cert)")
    private File publicKeyFile;

    @CommandLine.Option(names = {"--stream"}, description = "Whether to use streamed parsing")
    private boolean stream = false;

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getSecretKey() {
        return secretKey;
    }

    @Override
    public String getSecretKeyIdentifier() {
        return secretKeyIdentifier;
    }

    @Override
    public File getCertificateFile() {
        return certificateFile;
    }

    @Override
    public File getRecipientCertificateFile() {
        return recipientCertificateFile;
    }

    @Override
    public File getSenderCertificateFile() {
        return senderCertificateFile;
    }

    @Override
    public File getPrivateKeyFile() {
        return privateKeyFile;
    }

    @Override
    public File getPublicKeyFile() {
        return publicKeyFile;
    }

    @Override
    public boolean isStream() {
        return stream;
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
