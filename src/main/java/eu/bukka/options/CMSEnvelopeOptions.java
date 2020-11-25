package eu.bukka.options;

public interface CMSEnvelopeOptions extends CommonOptions {
    public String getAlgorithm();

    public String getSecretKey();

    public String getSecretKeyIdentifier();
}
