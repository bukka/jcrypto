package eu.bukka.cms.options;

public interface CMSEnvelopeOptions extends CMSCommonOptions {
    public String getAlgorithm();

    public String getSecretKey();

    public String getSecretKeyIdentifier();
}
