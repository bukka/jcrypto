package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.options.PKeyOptions;
import eu.bukka.jcrypto.pkey.KeyAgreementEnvelope;
import eu.bukka.jcrypto.pkey.KeyGeneratorEnvelope;
import eu.bukka.jcrypto.pkey.SignatureEnvelope;
import eu.bukka.jcrypto.server.PKeyServer;
import picocli.CommandLine;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;
import java.util.concurrent.Callable;

@CommandLine.Command(name = "pkey", mixinStandardHelpOptions = true,
        description = "Public and private key utils.")
public class PKeyCommand extends CommonCommand implements Callable<Integer>, PKeyOptions {
    @CommandLine.Parameters(index = "0", description = "Action")
    private String action;

    @CommandLine.Parameters(index = "1", arity = "0..1", description = "Sub Action")
    private String subAction;

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

    @CommandLine.Option(names = {"--port"}, description = "Port for the server (default: 8080)")
    private int port = 8080;

    @CommandLine.Option(names = {"--pid-file"}, description = "File to store server PID")
    private File pidFile;

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
            case "server":
                if ("start".equalsIgnoreCase(subAction)) {
                    PKeyServer server = new PKeyServer(this, port);

                    if (pidFile != null) {
                        try (PrintWriter writer = new PrintWriter(new FileWriter(pidFile))) {
                            writer.println(ProcessHandle.current().pid());
                        }
                    }

                    server.start();
                } else if ("stop".equalsIgnoreCase(subAction)) {
                    if (pidFile == null || !pidFile.exists()) {
                        throw new Exception("PID file not found. Is the server running?");
                    }

                    // Read the PID and stop the server
                    String pidString = new String(Files.readAllBytes(Paths.get(pidFile.getPath()))).trim();
                    long pid = Long.parseLong(pidString);

                    ProcessHandle.of(pid).ifPresentOrElse(
                            processHandle -> {
                                processHandle.destroy();
                            },
                            () -> {
                                System.out.println("No process found with PID: " + pid);
                            }
                    );

                    // Clean up PID file
                    pidFile.delete();
                } else {
                    throw new Exception("Unknown sub action: " + action);
                }
                break;
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
