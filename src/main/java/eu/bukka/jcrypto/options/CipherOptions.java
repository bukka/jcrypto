package eu.bukka.jcrypto.options;

import java.io.File;

public interface CipherOptions extends CommonOptions {
    String getAlgorithm();

    String getKey();

    String getIv();

    File getIvOutputFile();

    String getPadding();
}
