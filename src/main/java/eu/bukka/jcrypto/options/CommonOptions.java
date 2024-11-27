package eu.bukka.jcrypto.options;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Provider;

public interface CommonOptions {
    String getForm();

    String getProviderName();

    Provider getProvider();

    File getProviderConfigFile();

    File getInputFile();

    byte[] getInputData() throws IOException;

    File getOutputFile() throws IOException;

    OutputStream getOutputStream() throws IOException;

    void writeData(File dataFile, byte[] data) throws IOException;

    void writeOutputData(byte[] data) throws IOException;
}
