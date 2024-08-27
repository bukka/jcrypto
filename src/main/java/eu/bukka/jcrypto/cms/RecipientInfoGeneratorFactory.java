package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class RecipientInfoGeneratorFactory extends RecipientData {
    public RecipientInfoGeneratorFactory(CMSEnvelopeOptions options) {
        super(options);
    }

    private RecipientInfoGenerator createForKEK() {
        return new JceKEKRecipientInfoGenerator(getSecretKeyId(), getSecretKey()).setProvider("BC");
    }

    private ASN1ObjectIdentifier getKeyAgreeOID() throws CMSException {
        if (getSenderCertificate().getPublicKey().getAlgorithm().equalsIgnoreCase("DH")) {
            return PKCSObjectIdentifiers.dhKeyAgreement;
        } else {
            return CMSAlgorithm.ECDH_SHA256KDF;
        }
    }

    private ASN1ObjectIdentifier getKeyEncOID() throws CMSException {
        return CMSAlgorithm.AES128_WRAP;
    }

    private RecipientInfoGenerator createForKeyAgree() throws CMSException {
        try {
            JceKeyAgreeRecipientInfoGenerator generator = new JceKeyAgreeRecipientInfoGenerator(getKeyAgreeOID(),
                    getPrivateKey(), getSenderCertificate().getPublicKey(), getKeyEncOID());
            return generator.addRecipient(getRecipientCertificate()).setProvider("BC");
        } catch (CMSException|CertificateEncodingException e) {
            throw new CMSException("Failed to create KeyAgree recipient info generator", e);
        }
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
        } else if (options.getSenderCertificateFile() != null) {
            return createForKeyAgree();
        } else if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            return createForKEK();
        } else {
            throw new CMSException("No options to create recipient info");
        }
    }
}
