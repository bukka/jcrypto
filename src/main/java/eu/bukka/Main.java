package eu.bukka;

import eu.bukka.cli.CMSCommand;
import eu.bukka.cli.TopCommand;
import picocli.CommandLine;

public class Main {
    public static void main(String[] args) throws Exception {
        CommandLine cmd = new CommandLine(new TopCommand())
                .addSubcommand("cms", new CMSCommand());

        int exitCode = cmd.execute(args);

        System.exit(exitCode);
    }
}
