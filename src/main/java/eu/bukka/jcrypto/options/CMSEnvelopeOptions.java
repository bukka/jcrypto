package eu.bukka.jcrypto.options;

import java.io.File;

public interface CMSEnvelopeOptions extends CommonOptions {
    String getAlgorithm();

    String getContentType();

    String getSecretKey();

    String getSecretKeyIdentifier();

    String getPassword();

    String getKeyAlgorithm();

    File getCertificateFile();

    File getRecipientCertificateFile();

    File getSenderCertificateFile();

    File getPrivateKeyFile();

    File getPublicKeyFile();

    boolean isStream();
}
