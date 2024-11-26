package eu.bukka.jcrypto.options;

import java.io.File;
import java.io.IOException;

public interface PKeyOptions extends CommonOptions {
    String getAlgorithm();

    String getPrivateKeyAlias();

    File getPrivateKeyFile();

    byte[] getPrivateKeyFileData() throws IOException;

    String getPublicKeyAlias();

    File getPublicKeyFile();

    byte[] getPublicKeyFileData() throws IOException;

    File getSignatureFile();

    byte[] getSignatureFileData() throws IOException;

    String getKeyStoreName();

    String getKeyStorePassword();
}
