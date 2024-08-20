package eu.bukka.jcrypto.cms;

abstract public class CMSBase {
    protected RecipientInfoGeneratorFactory recipientInfoGeneratorFactory;
    protected RecipientHandler recipientHandler;

    public CMSBase(RecipientInfoGeneratorFactory recipientInfoGeneratorFactory, RecipientHandler recipientHandler) {
        this.recipientInfoGeneratorFactory = recipientInfoGeneratorFactory;
        this.recipientHandler = recipientHandler;
    }
}
