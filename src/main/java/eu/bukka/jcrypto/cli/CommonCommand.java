package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.options.CommonOptions;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;

import java.io.*;
import java.nio.file.Files;
import java.security.Provider;
import java.security.Security;
import java.util.Objects;

public class CommonCommand implements CommonOptions {
    @CommandLine.Option(names = {"-i", "--in"}, description = "Input file", required = true)
    private File inputFile;

    @CommandLine.Option(names = {"-o", "--out"}, description = "Output file")
    private File outputFile;

    @CommandLine.Option(names = {"-f", "--form"}, description = "Input and output form")
    private String form = "PEM";

    @CommandLine.Option(names = {"--provider"}, description = "Preferred provider name")
    private String provider = "BC";

    @CommandLine.Option(names = {"--provider-config-file"}, description = "Preferred provider config file")
    private File providerConfigFile;

    @Override
    public File getInputFile() {
        return inputFile;
    }

    @Override
    public File getOutputFile() {
        return outputFile;
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return Files.newOutputStream(outputFile.toPath());
    }

    @Override
    public String getForm() {
        return form;
    }

    @Override
    public String getProvider() {
        return provider;
    }

    @Override
    public File getProviderConfigFile() {
        return providerConfigFile;
    }

    protected byte[] getFileData(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }

    @Override
    public byte[] getInputData() throws IOException {
        return getFileData(getInputFile());
    }

    @Override
    public void writeData(File dataFile, byte[] data) throws IOException {
        FileUtils.writeByteArrayToFile(dataFile, data);
    }

    @Override
    public void writeOutputData(byte[] data) throws IOException {
        writeData(getOutputFile(), data);
    }

    protected void addSecurityProviders(boolean alwaysAddBouncyCastle) throws SecurityException {
        Security.setProperty("crypto.policy", "unlimited");
        if (alwaysAddBouncyCastle || Objects.equals(provider, "BC")) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Objects.equals(provider, "PKCS11")) {
            if (providerConfigFile == null) {
                throw new SecurityException("PKCS11 provider config file not set");
            }
            Provider pkcs11Provider = Security.getProvider("SunPKCS11");
            if (pkcs11Provider == null) {
                throw new SecurityException("SunPKCS11 provider not available");
            }
            pkcs11Provider = pkcs11Provider.configure(providerConfigFile.getAbsolutePath());
            Security.addProvider(pkcs11Provider);
        }
    }

    protected void addSecurityProviders() throws SecurityException {
        addSecurityProviders(false);
    }
}
