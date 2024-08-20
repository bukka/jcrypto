# jCrypto

The jCrypto is a command line tool for crypto operations. It is primarily a wrapper around Bouncy Castle and at this
stage more an integration testing tool.

## Installation

The tool is using Maven and can be installed using

```
mvn clean install
```

It will install a package with all dependencies. To run the jar, the following should be executed

```
java -cp target/jcrypto-1.0-SNAPSHOT-jar-with-dependencies.jar eu.bukka.jcrypto.Main <arguments>
```

For easier usage, the shell wrapper can be created. An example of that can be seen at [common.sh](examples/common.sh)
script that is sourced from all examples.

The tool is using picocli library so it offers an automatic help which can be seen by running

```
java -cp target/jcrypto-1.0-SNAPSHOT-jar-with-dependencies.jar eu.bukka.jcrypto.Main --help
```
