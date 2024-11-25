package eu.bukka.jcrypto;

import eu.bukka.jcrypto.cli.CMSCommand;
import eu.bukka.jcrypto.cli.CipherCommand;
import eu.bukka.jcrypto.cli.MailCommand;
import eu.bukka.jcrypto.cli.TopCommand;
import picocli.CommandLine;

public class Main {
    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new TopCommand())
                .addSubcommand("cipher", new CipherCommand())
                .addSubcommand("cms", new CMSCommand())
                .addSubcommand("mail", new MailCommand());

        int exitCode = cmd.execute(args);

        System.exit(exitCode);
    }
}
