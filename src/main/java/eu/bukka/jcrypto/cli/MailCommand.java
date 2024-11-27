package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.mail.smime.SMIMEEnvelope;
import eu.bukka.jcrypto.options.MailSMIMEEnvelopeOptions;
import picocli.CommandLine;

import java.io.File;
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

    @CommandLine.Option(names = {"--cert"}, description = "Certificate for KeyTrans recipient type")
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

    @CommandLine.Option(names = {"--from"}, description = "Mail From")
    private String mailFrom;

    @CommandLine.Option(names = {"--to"}, description = "Mail To")
    private String mailTo;

    @CommandLine.Option(names = {"--subject"}, description = "Mail subject")
    private String mailSubject;

    @CommandLine.Option(names = {"--mime-type"}, description = "Mail content mime type")
    private String mimeType = "text/plain";

    @CommandLine.Option(names = {"--charset"}, description = "Charset for text mime type")
    private String charset = "UTF-8";

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
    public String getCharset() {
        return charset;
    }

    @Override
    public String getMimeType() {
        return mimeType;
    }

    @Override
    public boolean isStream() {
        return stream;
    }

    @Override
    public Integer call() throws Exception {
        addSecurityProviders(true);
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
