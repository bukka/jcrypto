package eu.bukka.jcrypto.options;

import java.io.File;

public interface CipherOptions extends CommonOptions {
    public String getAlgorithm();

    public String getKey();

    public String getIv();

    public File getIvOutputFile();

    public String getPadding();
}
