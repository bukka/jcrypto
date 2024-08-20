package eu.bukka.jcrypto.options;

import java.io.File;

public interface CMSEnvelopeOptions extends CommonOptions {
    public String getAlgorithm();

    public String getSecretKey();

    public String getSecretKeyIdentifier();

    public File getCertificateFile();

    public File getPrivateKeyFile();
}
