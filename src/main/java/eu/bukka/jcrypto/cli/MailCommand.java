package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.mail.smime.SMIMEEnvelope;
import eu.bukka.jcrypto.options.MailSMIMEEnvelopeOptions;
import picocli.CommandLine;

import java.io.File;
import java.util.Map;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "mail", mixinStandardHelpOptions = true, showDefaultValues = true, usageHelpWidth = 100,
        description = {
                "Generate and open S/MIME enveloped messages.",
                "Recipient type is selected like the cms command (KeyTrans via --cert is typical)."
        },
        footer = {
                "",
                "Examples:",
                "  Encrypt to a recipient certificate:",
                "    jcrypto mail encrypt -c aes-128-cbc --cert recipient.pem \\",
                "      --from alice@example.com --to bob@example.com --subject Hello -i in.txt -o out.eml",
                "  Decrypt with the recipient private key:",
                "    jcrypto mail decrypt -c aes-128-cbc --cert recipient.pem --private-key recipient.key \\",
                "      -i out.eml -o dec.txt"
        })
public class MailCommand extends CommonCommand implements Callable<Integer>, MailSMIMEEnvelopeOptions {
    @CommandLine.Parameters(index = "0", paramLabel = "<mode>", description = "Operation: encrypt or decrypt")
    private String mode;

    @CommandLine.Option(names = {"-c", "--cipher"},
            description = "Content cipher: aes-128-cbc, aes-256-cbc, aes-128-gcm or aes-256-gcm (GCM is AEAD).")
    private String algorithm = "aes-256-cbc";

    @CommandLine.Option(names = {"--content-type"},
            description = "Force output structure for AEAD ciphers: enveloped-data or authEnveloped-data.")
    private String contentType;

    @CommandLine.Option(names = {"--secret-key"}, description = "KEK recipient: shared secret key, in hex.")
    private String secretKey;

    @CommandLine.Option(names = {"--secret-key-id"},
            description = "KEK recipient: key identifier, in hex; paired with --secret-key.")
    private String secretKeyIdentifier;

    @CommandLine.Option(names = {"--password"}, description = "Password recipient: password.")
    private String password;

    @CommandLine.Option(names = {"--key-algorithm"},
            description = "Password recipient: key-encryption cipher (defaults to --cipher).")
    private String keyAlgorithm;

    @CommandLine.Option(names = {"--cert"}, description = "KeyTrans recipient: recipient certificate (PEM).")
    private File certificateFile;

    @CommandLine.Option(names = {"--sender-cert"},
            description = "KeyAgree recipient: sender/originator certificate (PEM).")
    private File senderCertificateFile;

    @CommandLine.Option(names = {"--recipient-cert"},
            description = "KeyAgree recipient: recipient certificate (PEM).")
    private File recipientCertificateFile;

    @CommandLine.Option(names = {"--private-key"},
            description = "Private key (PEM): recipient key when decrypting (KeyTrans/KeyAgree).")
    private File privateKeyFile;

    @CommandLine.Option(names = {"--public-key"},
            description = "KeyAgree recipient: recipient public key (alternative to --recipient-cert).")
    private File publicKeyFile;

    @CommandLine.Option(names = {"--from"}, description = "Mail From header.")
    private String mailFrom;

    @CommandLine.Option(names = {"--to"}, description = "Mail To header.")
    private String mailTo;

    @CommandLine.Option(names = {"--subject"}, description = "Mail Subject header.")
    private String mailSubject;

    @CommandLine.Option(names = {"--mime-type"}, description = "Content MIME type.")
    private String mimeType = "text/plain";

    @CommandLine.Option(names = {"--charset"}, description = "Charset for text MIME types.")
    private String charset = "UTF-8";

    @CommandLine.Option(names = {"--stream"}, description = "Use streamed S/MIME parsing.")
    private boolean stream = false;

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getContentType() {
        return contentType;
    }

    @Override
    public Map<String, String> getAuthenticatedAttributes() {
        return null;
    }

    @Override
    public Map<String, String> getUnauthenticatedAttributes() {
        return null;
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
    public String getPassword() {
        return password;
    }

    @Override
    public String getKeyAlgorithm() {
        return keyAlgorithm;
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
