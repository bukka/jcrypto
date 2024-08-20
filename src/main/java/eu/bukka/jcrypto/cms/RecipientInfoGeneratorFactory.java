package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import java.security.cert.CertificateException;

public class RecipientInfoGeneratorFactory extends RecipientData {
    public RecipientInfoGeneratorFactory(CMSEnvelopeOptions options) {
        super(options);
    }

    private RecipientInfoGenerator createForKEK() {
        return new JceKEKRecipientInfoGenerator(getSecretKeyId(), getSecretKey()).setProvider("BC");
    }

    private RecipientInfoGenerator createForKeyTrans() throws CMSException {
        try {
            return new JceKeyTransRecipientInfoGenerator(getCertificate()).setProvider("BC");
        } catch (CertificateException e) {
            throw new CMSException("Failed to create KeyTrans recipient info generator", e);
        }
    }

    public RecipientInfoGenerator create() throws CMSException {
        if (options.getCertificateFile() != null) {
            return createForKeyTrans();
        } else if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            return createForKEK();
        } else {
            throw new CMSException("No options to create recipient info");
        }
    }
}
