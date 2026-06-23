package eu.bukka.jcrypto.cli;

import picocli.CommandLine;

@CommandLine.Command(name = "jcrypto", mixinStandardHelpOptions = true,
        description = "Command line tool for crypto operations, primarily a wrapper around Bouncy Castle. "
                + "Run 'jcrypto <command> --help' for command details and examples.")
public class TopCommand {
}
