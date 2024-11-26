package eu.bukka.jcrypto;

import eu.bukka.jcrypto.cli.*;
import picocli.CommandLine;

public class Main {
    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new TopCommand())
                .addSubcommand("cipher", new CipherCommand())
                .addSubcommand("cms", new CMSCommand())
                .addSubcommand("mail", new MailCommand())
                .addSubcommand("pkey", new PKeyCommand());

        int exitCode = cmd.execute(args);

        System.exit(exitCode);
    }
}
