package eu.bukka.jcrypto.options;

public interface CipherOptions extends CommonOptions {
    public String getAlgorithm();

    public String getKey();

    public String getIv();

    public String getPadding();
}
