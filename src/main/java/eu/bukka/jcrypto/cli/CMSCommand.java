package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.cms.CMSEnvelope;
import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.File;
import java.util.Map;
import java.util.concurrent.Callable;

@Command(name = "cms", mixinStandardHelpOptions = true, showDefaultValues = true, usageHelpWidth = 100,
        description = {
                "Generate and open RFC 5652 CMS enveloped-data and authEnveloped-data.",
                "The recipient type is selected by which options you provide:",
                "  KEK       --secret-key + --secret-key-id",
                "  KeyTrans  --cert (encrypt), --cert + --private-key (decrypt)",
                "  KeyAgree  --sender-cert + --private-key + --recipient-cert (encrypt),",
                "            --recipient-cert + --private-key (decrypt)",
                "  Password  --password",
                "An AEAD cipher (GCM) produces authEnveloped-data unless --content-type overrides it."
        },
        footer = {
                "",
                "Examples:",
                "  KEK (shared secret):",
                "    jcrypto cms encrypt -c aes-128-cbc --secret-key=000102030405060708090a0b0c0d0e0f \\",
                "      --secret-key-id=C0FEE0 -i in.txt -o out.pem",
                "    jcrypto cms decrypt -c aes-128-cbc --secret-key=000102030405060708090a0b0c0d0e0f \\",
                "      --secret-key-id=C0FEE0 -i out.pem -o dec.txt",
                "  KeyTrans (RSA):",
                "    jcrypto cms encrypt -c aes-128-cbc --cert recipient.pem -i in.txt -o out.pem",
                "    jcrypto cms decrypt -c aes-128-cbc --cert recipient.pem --private-key recipient.key \\",
                "      -i out.pem -o dec.txt",
                "  KeyAgree (EC):",
                "    jcrypto cms encrypt -c aes-128-gcm --sender-cert sender.pem --private-key sender.key \\",
                "      --recipient-cert recipient.pem -i in.txt -o out.pem",
                "    jcrypto cms decrypt -c aes-128-gcm --recipient-cert recipient.pem \\",
                "      --private-key recipient.key -i out.pem -o dec.txt",
                "  authEnveloped-data with attributes (GCM):",
                "    jcrypto cms encrypt -c aes-128-gcm --secret-key=000102030405060708090a0b0c0d0e0f \\",
                "      --secret-key-id=C0FEE0 --auth-attr 1.3.6.1.4.1.99999.1=hello \\",
                "      --unauth-attr 1.3.6.1.4.1.99999.2=world -i in.txt -o out.pem",
                "  authenticated-data (MAC only, HMAC-SHA256):",
                "    jcrypto cms encrypt --content-type authenticated-data \\",
                "      --secret-key=000102030405060708090a0b0c0d0e0f --secret-key-id=C0FEE0 -i in.txt -o out.pem"
        })
public class CMSCommand extends CommonCommand implements Callable<Integer>, CMSEnvelopeOptions {
    @Parameters(index = "0", paramLabel = "<mode>", description = "Operation: encrypt or decrypt")
    private String mode;

    @Option(names = {"-c", "--cipher"},
            description = "Content cipher: aes-128-cbc, aes-256-cbc, aes-128-gcm or aes-256-gcm (GCM is AEAD).")
    private String algorithm = "aes-256-cbc";

    @Option(names = {"--content-type"},
            description = "Output structure: enveloped-data, authEnveloped-data (default for GCM) or "
                    + "authenticated-data (MAC only, no encryption).")
    private String contentType;

    @Option(names = {"--mac-algorithm"},
            description = "authenticated-data MAC: sha1, sha224, sha256 (default), sha384 or sha512 (HMAC).")
    private String macAlgorithm;

    @Option(names = {"--auth-attr"}, description = "authEnveloped-data only: authenticated attribute as "
            + "OID=value (repeatable); covered by the AEAD tag.")
    private Map<String, String> authenticatedAttributes;

    @Option(names = {"--unauth-attr"}, description = "authEnveloped-data only: unauthenticated attribute as "
            + "OID=value (repeatable).")
    private Map<String, String> unauthenticatedAttributes;

    @Option(names = {"--secret-key"}, description = "KEK recipient: shared secret key, in hex.")
    private String secretKey;

    @Option(names = {"--secret-key-id"},
            description = "KEK recipient: key identifier, in hex; paired with --secret-key.")
    private String secretKeyIdentifier;

    @Option(names = {"--password"}, description = "Password recipient: password.")
    private String password;

    @Option(names = {"--key-algorithm"},
            description = "Password recipient: key-encryption cipher (defaults to --cipher).")
    private String keyAlgorithm;

    @Option(names = {"--cert"}, description = "KeyTrans recipient: recipient certificate (PEM).")
    private File certificateFile;

    @CommandLine.Option(names = {"--sender-cert"},
            description = "KeyAgree recipient: sender/originator certificate (PEM).")
    private File senderCertificateFile;

    @CommandLine.Option(names = {"--recipient-cert"},
            description = "KeyAgree recipient: recipient certificate (PEM).")
    private File recipientCertificateFile;

    @CommandLine.Option(names = {"--private-key"},
            description = "Private key (PEM): originator key when encrypting (KeyAgree), "
                    + "or recipient key when decrypting (KeyTrans/KeyAgree).")
    private File privateKeyFile;

    @CommandLine.Option(names = {"--public-key"},
            description = "KeyAgree recipient: recipient public key (alternative to --recipient-cert).")
    private File publicKeyFile;

    @CommandLine.Option(names = {"--stream"},
            description = "Use streamed parsing (SMIME only; no effect on cms).")
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
    public String getMacAlgorithm() {
        return macAlgorithm;
    }

    @Override
    public Map<String, String> getAuthenticatedAttributes() {
        return authenticatedAttributes;
    }

    @Override
    public Map<String, String> getUnauthenticatedAttributes() {
        return unauthenticatedAttributes;
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
    public boolean isStream() {
        return stream;
    }

    @Override
    public Integer call() throws Exception {
        addSecurityProviders(true);
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
