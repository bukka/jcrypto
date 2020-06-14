package eu.bukka.service.options;

public interface CMSEnvelopedDataOptions extends CMSCommonOptions {
    public String getAlgorithm();

    public String getSecretKey();

    public String getSecretKeyIdentifier();
}
