package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;

abstract public class CMSBase extends CMSContent<CMSEnvelopeOptions> {
    protected RecipientInfoGeneratorFactory recipientInfoGeneratorFactory;
    protected RecipientHandler recipientHandler;

    public CMSBase(CMSEnvelopeOptions options, RecipientInfoGeneratorFactory recipientInfoGeneratorFactory,
                   RecipientHandler recipientHandler) {
        super(options);
        this.recipientInfoGeneratorFactory = recipientInfoGeneratorFactory;
        this.recipientHandler = recipientHandler;
    }

    public CMSBase(CMSEnvelopeOptions options) {
        this(options, new RecipientInfoGeneratorFactory(options), new RecipientHandler(options));
    }
}
