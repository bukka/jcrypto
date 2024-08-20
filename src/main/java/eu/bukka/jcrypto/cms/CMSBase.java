package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;

abstract public class CMSBase {
    protected RecipientInfoGeneratorFactory recipientInfoGeneratorFactory;
    protected RecipientHandler recipientHandler;

    public CMSBase(RecipientInfoGeneratorFactory recipientInfoGeneratorFactory, RecipientHandler recipientHandler) {
        this.recipientInfoGeneratorFactory = recipientInfoGeneratorFactory;
        this.recipientHandler = recipientHandler;
    }

    public CMSBase(CMSEnvelopeOptions options) {
        this(new RecipientInfoGeneratorFactory(options), new RecipientHandler(options));
    }
}
