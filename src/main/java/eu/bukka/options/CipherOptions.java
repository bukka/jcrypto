package eu.bukka.options;

public interface CipherOptions extends CommonOptions {
    public String getAlgorithm();

    public String getKey();

    public String getIv();
}
