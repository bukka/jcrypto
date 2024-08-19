package eu.bukka.jcrypto.options;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;

public interface CommonOptions {
    public String getForm();

    public File getInputFile();

    public byte[] getInputData() throws IOException;

    public File getOutputFile() throws IOException;

    public OutputStream getOutputStream() throws IOException;

    public void writeData(File dataFile, byte[] data) throws IOException;

    public void writeOutputData(byte[] data) throws IOException;
}
