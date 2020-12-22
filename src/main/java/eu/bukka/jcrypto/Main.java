package eu.bukka.jcrypto;

import eu.bukka.jcrypto.cli.CMSCommand;
import eu.bukka.jcrypto.cli.CipherCommand;
import eu.bukka.jcrypto.cli.TopCommand;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import picocli.CommandLine;

import java.security.Security;

public class Main {
    public static void main(String[] args) throws Exception {
        Security.setProperty("crypto.policy", "unlimited");
        Security.addProvider(new BouncyCastleProvider());

        CommandLine cmd = new CommandLine(new TopCommand())
                .addSubcommand("cipher", new CipherCommand())
                .addSubcommand("cms", new CMSCommand());

        int exitCode = cmd.execute(args);

        System.exit(exitCode);
    }
}
