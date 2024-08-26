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
        return new JceKeyAgreeRecipientId(getCertificate());
    }

    private RecipientId createRecipientIdForKeyTrans() throws CMSException {
        return new JceKeyTransRecipientId(getCertificate());
    }

    private RecipientId createRecipientId() throws CMSException {
        if (options.getCertificateFile() != null) {
            if (isCertificateForKeyAgree()) {
                return createRecipientIdForKeyAgree();
            } else {
                return createRecipientIdForKeyTrans();
            }
        } else if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            return createRecipientIdForKEK();
        } else {
            throw new CMSException("No options to create recipient ID");
        }
    }

    private Recipient createRecipientForKEK(boolean isAEAD) throws CMSException {
        if (isAEAD && options.isStream()) {
            return new JceKEKAuthEnvelopedRecipient(getSecretKey()).setProvider("BC");
        }
        return new JceKEKEnvelopedRecipient(getSecretKey()).setProvider("BC");
    }

    private Recipient createRecipientForKeyAgree(boolean isAEAD) throws CMSException {
        if (isAEAD) {
            return new JceKeyAgreeAuthEnvelopedRecipient(getPrivateKey()).setProvider("BC");
        }
        return new JceKeyAgreeEnvelopedRecipient(getPrivateKey()).setProvider("BC");
    }

    private Recipient createRecipientForKeyTrans(boolean isAEAD) throws CMSException {
        if (isAEAD) {
            return new JceKeyTransAuthEnvelopedRecipient(getPrivateKey()).setProvider("BC");
        }
        return new JceKeyTransEnvelopedRecipient(getPrivateKey()).setProvider("BC");
    }

    private Recipient createRecipient(boolean isAEAD) throws CMSException {
        if (options.getCertificateFile() != null) {
            if (options.getPrivateKeyFile() == null) {
                throw new CMSException("Private key is required to create recipient");
            }
            if (isCertificateForKeyAgree()) {
                return createRecipientForKeyAgree(isAEAD);
            }
            return createRecipientForKeyTrans(isAEAD);
        }
        return createRecipientForKEK(isAEAD);
    }

    public byte[] getContent(RecipientInformationStore recipients, boolean isAEAD) throws CMSException {
        RecipientId recipientId = createRecipientId();
        RecipientInformation recipientInformation = recipients.get(recipientId);
        return recipientInformation.getContent(createRecipient(isAEAD));
    }
}
