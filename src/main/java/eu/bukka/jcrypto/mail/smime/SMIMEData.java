package eu.bukka.jcrypto.mail.smime;

import eu.bukka.jcrypto.cms.CMSBase;
import eu.bukka.jcrypto.cms.RecipientHandler;
import eu.bukka.jcrypto.cms.RecipientInfoGeneratorFactory;
import eu.bukka.jcrypto.mail.smime.bc.SMIMEAuthEnvelopedGenerator;
import eu.bukka.jcrypto.options.MailSMIMEEnvelopeOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;

import java.security.InvalidParameterException;

abstract public class SMIMEData extends CMSBase {
    protected MailSMIMEEnvelopeOptions options;

    protected static class Algorithm {
        private final ASN1ObjectIdentifier identifier;
        private final String name;
        private final boolean authenticated;

        public Algorithm(String name, ASN1ObjectIdentifier identifier, boolean authenticate) {
            this.name = name;
            this.identifier = identifier;
            this.authenticated = authenticate;
        }

        public Algorithm(String name, ASN1ObjectIdentifier identifier) {
            this.name = name;
            this.identifier = identifier;
            this.authenticated = false;
        }

        public boolean isAuthenticated() {
            return authenticated;
        }

        public String getName() {
            return name;
        }

        public ASN1ObjectIdentifier getIdentifier() {
            return identifier;
        }
    }

    public SMIMEData(MailSMIMEEnvelopeOptions options, RecipientInfoGeneratorFactory recipientInfoGeneratorFactory,
                     RecipientHandler recipientHandler) {
        super(recipientInfoGeneratorFactory, recipientHandler);
        this.options = options;
    }

    public SMIMEData(MailSMIMEEnvelopeOptions options) {
        super(options);
        this.options = options;
    }

    protected Algorithm getAlgorithm() {
        String algorithm = options.getAlgorithm().toUpperCase();
        switch (algorithm) {
            case "AES128_GCM":
            case "AES-128-GCM":
                return new Algorithm(SMIMEAuthEnvelopedGenerator.AES128_GCM, CMSAlgorithm.AES128_GCM, true);
            case "AES256_GCM":
            case "AES-256-GCM":
                return new Algorithm(SMIMEAuthEnvelopedGenerator.AES256_GCM, CMSAlgorithm.AES256_GCM, true);
            case "AES128_CBC":
            case "AES-128-CBC":
                return new Algorithm(SMIMEEnvelopedGenerator.AES128_CBC, CMSAlgorithm.AES128_CBC);
            case "AES256_CBC":
            case "AES-256-CBC":
                return new Algorithm(SMIMEEnvelopedGenerator.AES256_CBC, CMSAlgorithm.AES256_CBC);
            default:
                throw new InvalidParameterException("Invalid algorithm " + algorithm);
        }
    }
}
