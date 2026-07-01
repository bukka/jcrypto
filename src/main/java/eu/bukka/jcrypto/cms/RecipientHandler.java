package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.bc.cms.jcajce.JceKEKAuthEnvelopedRecipient;
import eu.bukka.jcrypto.bc.cms.jcajce.JceKeyAgreeAuthEnvelopedRecipient;
import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;

public class RecipientHandler extends RecipientData {
    public RecipientHandler(CMSEnvelopeOptions options) {
        super(options);
    }

    private RecipientId createRecipientIdForKEK() {
        return new KEKRecipientId(getSecretKeyId());
    }

    private RecipientId createRecipientIdForKeyAgree() throws CMSException {
        return new JceKeyAgreeRecipientId(getRecipientCertificate());
    }

    private RecipientId createRecipientIdForKeyTrans() throws CMSException {
        return new JceKeyTransRecipientId(getCertificate());
    }

    private RecipientId createRecipientId() throws CMSException {
        if (options.getRecipientCertificateFile() != null) {
            return createRecipientIdForKeyAgree();
        } else if (options.getCertificateFile() != null) {
            return createRecipientIdForKeyTrans();
        } else if (options.getSecretKey() != null) {
            return createRecipientIdForKEK();
        } else {
            throw new CMSException("No options to create recipient ID");
        }
    }

    private Recipient createRecipientForKEK(CMSStructure structure) throws CMSException {
        switch (structure) {
            case AUTH_ENVELOPED:
                return new JceKEKAuthEnvelopedRecipient(getSecretKey()).setProvider("BC");
            case AUTHENTICATED:
                return new JceKEKAuthenticatedRecipient(getSecretKey()).setProvider("BC");
            default:
                return new JceKEKEnvelopedRecipient(getSecretKey()).setProvider("BC");
        }
    }

    private Recipient createRecipientForKeyAgree(CMSStructure structure) throws CMSException {
        switch (structure) {
            case AUTH_ENVELOPED:
                return new JceKeyAgreeAuthEnvelopedRecipient(getPrivateKey()).setProvider("BC");
            case AUTHENTICATED:
                return new JceKeyAgreeAuthenticatedRecipient(getPrivateKey()).setProvider("BC");
            default:
                return new JceKeyAgreeEnvelopedRecipient(getPrivateKey()).setProvider("BC");
        }
    }

    private Recipient createRecipientForKeyTrans(CMSStructure structure) throws CMSException {
        switch (structure) {
            case AUTH_ENVELOPED:
                return new JceKeyTransAuthEnvelopedRecipient(getPrivateKey()).setProvider("BC");
            case AUTHENTICATED:
                return new JceKeyTransAuthenticatedRecipient(getPrivateKey()).setProvider("BC");
            default:
                return new JceKeyTransEnvelopedRecipient(getPrivateKey()).setProvider("BC");
        }
    }

    private Recipient createRecipient(CMSStructure structure) throws CMSException {
        if (options.getSecretKey() != null) {
            return createRecipientForKEK(structure);
        }
        if (options.getPrivateKeyFile() == null) {
            throw new CMSException("Private key is required to create recipient");
        }
        if (options.getRecipientCertificateFile() != null) {
            return createRecipientForKeyAgree(structure);
        }
        return createRecipientForKeyTrans(structure);
    }

    public byte[] getContent(RecipientInformationStore recipients, CMSStructure structure) throws CMSException {
        RecipientId recipientId = createRecipientId();
        RecipientInformation recipientInformation = recipients.get(recipientId);
        return recipientInformation.getContent(createRecipient(structure));
    }
}
