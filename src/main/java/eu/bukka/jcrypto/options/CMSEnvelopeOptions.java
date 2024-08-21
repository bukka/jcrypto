package eu.bukka.jcrypto.options;

import java.io.File;

public interface CMSEnvelopeOptions extends CommonOptions {
    String getAlgorithm();

    String getSecretKey();

    String getSecretKeyIdentifier();

    File getCertificateFile();

    File getPrivateKeyFile();

    boolean isStream();
}
