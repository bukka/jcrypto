package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.mail.smime.SMIMEEnvelope;
import eu.bukka.jcrypto.options.MailSMIMEEnvelopeOptions;
import picocli.CommandLine;

import java.util.concurrent.Callable;

@CommandLine.Command(name = "mail", mixinStandardHelpOptions = true,
        description = "Processing Mail using SMIME.")
public class MailCommand extends CommonCommand implements Callable<Integer>, MailSMIMEEnvelopeOptions {
    @CommandLine.Parameters(index = "0", description = "Mode")
    private String mode;

    @CommandLine.Option(names = {"-c", "--cipher"}, description = "Cipher to use")
    private String algorithm = "aes-256-cbc";

    @CommandLine.Option(names = {"--secret-key"}, description = "Secret key for KEK recipient type")
    private String secretKey;

    @CommandLine.Option(names = {"--secret-key-id"}, description = "Secret key for KEK recipient type")
    private String secretKeyIdentifier;

    @CommandLine.Option(names = {"--from"}, description = "Mail From")
    private String mailFrom;

    @CommandLine.Option(names = {"--to"}, description = "Mail To")
    private String mailTo;

    @CommandLine.Option(names = {"--subject"}, description = "Mail subject")
    private String mailSubject;

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
    public String getMailTo() {
        return mailTo;
    }

    @Override
    public String getMailFrom() {
        return mailFrom;
    }

    @Override
    public String getMailSubject() {
        return mailSubject;
    }

    @Override
    public Integer call() throws Exception {
        switch (mode) {
            case "encrypt":
                new SMIMEEnvelope(this).encrypt();
                break;
            case "decrypt":
                new SMIMEEnvelope(this).decrypt();
                break;
            default:
                throw new Exception("Unknown SMIME mode: " + mode);
        }

        return 0;
    }
}
