package eu.bukka.cli;

import eu.bukka.options.CommonOptions;
import org.apache.commons.io.FileUtils;
import picocli.CommandLine;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class CommonCommand implements CommonOptions {
    @CommandLine.Option(names = {"-i", "--in"}, description = "Input file", required = true)
    private File inputFile;

    @CommandLine.Option(names = {"-o", "--out"}, description = "Output file")
    private File outputFile;

    @CommandLine.Option(names = {"-f", "--form"}, description = "Input and output form")
    private String form = "PEM";

    public File getInputFile() {
        return inputFile;
    }

    public File getOutputFile() {
        return outputFile;
    }

    public String getForm() {
        return form;
    }

    public byte[] getInputData() throws IOException {
        return Files.readAllBytes(getInputFile().toPath());
    }

    public void writeOutputData(byte[] data) throws IOException {
        FileUtils.writeByteArrayToFile(getOutputFile(), data);
    }
}
