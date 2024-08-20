package eu.bukka.jcrypto.cli;

import eu.bukka.jcrypto.options.CommonOptions;
import org.apache.commons.io.FileUtils;
import picocli.CommandLine;

import java.io.*;
import java.nio.file.Files;

public class CommonCommand implements CommonOptions {
    @CommandLine.Option(names = {"-i", "--in"}, description = "Input file", required = true)
    private File inputFile;

    @CommandLine.Option(names = {"-o", "--out"}, description = "Output file")
    private File outputFile;

    @CommandLine.Option(names = {"-f", "--form"}, description = "Input and output form")
    private String form = "PEM";

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
    public byte[] getInputData() throws IOException {
        return Files.readAllBytes(getInputFile().toPath());
    }

    @Override
    public void writeData(File dataFile, byte[] data) throws IOException {
        FileUtils.writeByteArrayToFile(dataFile, data);
    }

    @Override
    public void writeOutputData(byte[] data) throws IOException {
        writeData(getOutputFile(), data);
    }
}
