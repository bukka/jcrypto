package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.options.PKeyOptions;
import eu.bukka.jcrypto.pkey.KeyAgreementEnvelope;
import eu.bukka.jcrypto.pkey.KeyGeneratorEnvelope;
import eu.bukka.jcrypto.pkey.SignatureEnvelope;
import picocli.CommandLine;

import java.io.File;
import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "pkey", mixinStandardHelpOptions = true,
        description = "Public and private key utils.")
public class PKeyCommand extends CommonCommand implements Callable<Integer>, PKeyOptions {
    @CommandLine.Parameters(index = "0", description = "Action")
    private String action;

    @CommandLine.Option(names = {"-a", "--algorithm"}, description = "Algorithm to use")
    private String algorithm;

    @CommandLine.Option(names = {"--private-key-file"}, description = "Private key file")
    private File privateKeyFile;

    @CommandLine.Option(names = {"--private-key-alias"}, description = "Private key alias")
    private String privateKeyAlias;

    @CommandLine.Option(names = {"--public-key-file"}, description = "Public key file")
    private File publicKeyFile;

    @CommandLine.Option(names = {"--public-key-alias"}, description = "Public key alias")
    private String publicKeyAlias;

    @CommandLine.Option(names = {"--signature-file"}, description = "Public key file")
    private File signatureFile;

    @CommandLine.Option(names = {"--key-store-name"}, description = "Key store name")
    private String keyStoreName;

    @CommandLine.Option(names = {"--key-store-password"}, description = "Key store password (PIN for PKCS11)")
    private String keyStorePassword;

    @CommandLine.Option(names = {"--parameters"}, description = "Algorithm-specific parameters (e.g., curve name for EC)")
    private String parameters;

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getPrivateKeyAlias() {
        return privateKeyAlias;
    }

    @Override
    public String getPublicKeyAlias() {
        return publicKeyAlias;
    }

    @Override
    public File getPrivateKeyFile() {
        return privateKeyFile;
    }

    @Override
    public byte[] getPrivateKeyFileData() throws IOException {
        return getFileData(privateKeyFile);
    }

    @Override
    public File getPublicKeyFile() {
        return publicKeyFile;
    }

    @Override
    public byte[] getPublicKeyFileData() throws IOException {
        return getFileData(publicKeyFile);
    }

    @Override
    public File getSignatureFile() {
        return signatureFile;
    }

    @Override
    public byte[] getSignatureFileData() throws IOException {
        return getFileData(signatureFile);
    }

    @Override
    public String getKeyStoreName() {
        return keyStoreName;
    }

    @Override
    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    @Override
    public String getParameters() {
        return parameters;
    }

    @Override
    public Integer call() throws Exception {
        addSecurityProviders(true);
        if (keyStoreName == null && Objects.equals(getProvider(), "SunPKCS11")) {
            keyStoreName = "PKCS11";
        }
        switch (action) {
            case "sign":
                new SignatureEnvelope(this).sign();
                break;
            case "verify":
                new SignatureEnvelope(this).verify();
                break;
            case "generate":
                new KeyGeneratorEnvelope(this).generate();
                break;
            case "derive":
                new KeyAgreementEnvelope(this).derive();
                break;
            default:
                throw new Exception("Unknown pkey action: " + action);
        }

        return 0;
    }
}
