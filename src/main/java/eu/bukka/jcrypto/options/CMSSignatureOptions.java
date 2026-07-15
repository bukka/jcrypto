package eu.bukka.jcrypto.options;

import java.io.File;

public interface CMSSignatureOptions extends CommonOptions {
    File getSignerCertificateFile();

    File getPrivateKeyFile();

    String getDigestAlgorithm();

    boolean isDetached();

    File getContentFile();
}
