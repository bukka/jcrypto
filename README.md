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

## Install to PATH

The repository ships a [bin/jcrypto](bin/jcrypto) wrapper that runs the assembly jar with all passed
arguments. To get a `jcrypto` command, symlink it into a directory on your `PATH`, for example:

```
ln -s "$(pwd)/bin/jcrypto" ~/.local/bin/jcrypto
```

The wrapper resolves the jar relative to its own location, so it always runs the latest build produced
by `mvn package` (no reinstall needed). After a `mvn clean`, just rebuild before using it again. Then the
tool can be run simply as

```
jcrypto <arguments>
```

The tool is using picocli library so it offers an automatic help which can be seen by running

```
jcrypto --help
```
