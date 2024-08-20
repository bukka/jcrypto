package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;

import java.security.InvalidParameterException;

abstract public class CMSData extends CMSBase {
    protected CMSEnvelopeOptions options;

    protected enum Form {
        DER,
        PEM,
        SMIME,
    }

    protected static class Algorithm {
        private final ASN1ObjectIdentifier identifier;
        private final boolean authenticated;

        public Algorithm(ASN1ObjectIdentifier identifier, boolean authenticate) {
            this.identifier = identifier;
            this.authenticated = authenticate;
        }

        public Algorithm(ASN1ObjectIdentifier identifier) {
            this.identifier = identifier;
            this.authenticated = false;
        }

        public boolean isAuthenticated() {
            return authenticated;
        }

        public ASN1ObjectIdentifier getIdentifier() {
            return identifier;
        }
    }

    public CMSData(CMSEnvelopeOptions options, RecipientInfoGeneratorFactory recipientInfoGeneratorFactory,
                   RecipientHandler recipientHandler) {
        super(recipientInfoGeneratorFactory, recipientHandler);
        this.options = options;
    }

    protected Algorithm getAlgorithm() {
        String algorithm = options.getAlgorithm().toUpperCase();
        switch (algorithm) {
            case "AES128_GCM":
            case "AES-128-GCM":
                return new Algorithm(CMSAlgorithm.AES128_GCM, true);
            case "AES256_GCM":
            case "AES-256-GCM":
                return new Algorithm(CMSAlgorithm.AES256_GCM, true);
            case "AES128_CBC":
            case "AES-128-CBC":
                return new Algorithm(CMSAlgorithm.AES128_CBC);
            case "AES256_CBC":
            case "AES-256-CBC":
                return new Algorithm(CMSAlgorithm.AES256_CBC);
            default:
                throw new InvalidParameterException("Invalid algorithm " + algorithm);
        }
    }

    protected Form getForm() {
        String form = options.getForm();
        switch (form) {
            case "DER":
                return Form.DER;
            case "PEM":
                return Form.PEM;
            case "SMIME":
                return Form.SMIME;
            default:
                throw new InvalidParameterException("Invalid form " + form);
        }
    }
}
