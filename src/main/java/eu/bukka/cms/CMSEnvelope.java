package eu.bukka.cms;

import eu.bukka.cms.options.CMSEnvelopeOptions;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileWriter;
import java.io.IOException;

public class CMSEnvelope extends CMSData {
    public CMSEnvelope(CMSEnvelopeOptions options) {
        super(options);
    }

    private byte[] getSecretKeyId() {
        return Strings.toByteArray(options.getSecretKeyIdentifier());
    }

    private SecretKey getSecretKey() {
        return new SecretKeySpec(Hex.decode(options.getSecretKey()), "AES");
    }

    public void encrypt() throws IOException, CMSException {
        CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();
        if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            // KEKRecipientInfo choice
            envGen.addRecipientInfoGenerator(
                    new JceKEKRecipientInfoGenerator(getSecretKeyId(), getSecretKey())
                            .setProvider("BC"));
        }
        CMSEnvelopedData envData = envGen.generate(
            new CMSProcessableByteArray(getInputData()),
            new JceCMSContentEncryptorBuilder(getAlgorithm()).setProvider("BC").build());
        if (getForm() == Form.PEM) {
            ContentInfo ci = ContentInfo.getInstance(ASN1Sequence.fromByteArray(envData.getEncoded()));
            JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(options.getOutputFile()));
            writer.writeObject(ci);
            writer.close();
        } else {
            FileUtils.writeByteArrayToFile(options.getOutputFile(), envData.getEncoded());
        }
    }

    private byte[] decryptKEK(CMSEnvelopedData envelopedData) throws CMSException {
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        RecipientId rid = new KEKRecipientId(getSecretKeyId());
        RecipientInformation recipient = recipients.get(rid);
        return recipient.getContent(
                new JceKEKEnvelopedRecipient(getSecretKey())
                        .setProvider("BC"));
    }

    public void decrypt() throws IOException, CMSException {
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(getInputData());
        byte[] decryptedData;
        if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            decryptedData = decryptKEK(envelopedData);
        } else {
            throw new IllegalArgumentException("Invalid arguments");
        }
        if (getForm() == Form.PEM) {
            JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(options.getOutputFile()));
            writer.write(Strings.fromByteArray(decryptedData));
            writer.close();
        } else {
            FileUtils.writeByteArrayToFile(options.getOutputFile(), decryptedData);
        }
    }
}
