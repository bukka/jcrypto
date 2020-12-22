package eu.bukka.jcrypto.options;

import java.io.File;
import java.io.IOException;

public interface CommonOptions {
    public String getForm();

    public File getInputFile();

    public byte[] getInputData() throws IOException;

    public File getOutputFile();

    public void writeOutputData(byte[] data) throws IOException;
}
