package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;

public class RecipientHandler extends RecipientData {
    public RecipientHandler(CMSEnvelopeOptions options) {
        super(options);
    }

    private RecipientId createRecipientIdForKEK() {
        return new KEKRecipientId(getSecretKeyId());
    }

    private RecipientId createRecipientIdForKeyTrans() throws CMSException {
        return new JceKeyTransRecipientId(getCertificate());
    }

    private RecipientId createRecipientId() throws CMSException {
        if (options.getCertificateFile() != null) {
            return createRecipientIdForKeyTrans();
        } else if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            return createRecipientIdForKEK();
        } else {
            throw new CMSException("No options to create recipient ID");
        }
    }

    private Recipient createRecipientForKEK() {
        return new JceKEKEnvelopedRecipient(getSecretKey()).setProvider("BC");
    }

    private Recipient createRecipientForKeyTrans() throws CMSException {
        return new JceKeyTransEnvelopedRecipient(getPrivateKey()).setProvider("BC");
    }

    private Recipient createRecipient() throws CMSException {
        if (options.getCertificateFile() != null) {
            if (options.getPrivateKeyFile() == null) {
                throw new CMSException("Private key is required to create recipient");
            }
            return createRecipientForKeyTrans();
        }
        return createRecipientForKEK();
    }

    public byte[] getContent(RecipientInformationStore recipients) throws CMSException {
        RecipientId recipientId = createRecipientId();
        RecipientInformation recipientInformation = recipients.get(recipientId);
        return recipientInformation.getContent(createRecipient());
    }
}
