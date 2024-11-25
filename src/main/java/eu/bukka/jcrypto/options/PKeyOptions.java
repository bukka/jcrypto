package eu.bukka.jcrypto.options;

import java.io.File;

public interface PKeyOptions extends CommonOptions {
    String getAlgorithm();

    String getPrivateKeyAlias();

    String getPublicKeyAlias();

    File getPrivateKeyFile();

    File getPublicKeyFile();

    String getKeyStoreName();

    String getKeyStorePassword();
}
