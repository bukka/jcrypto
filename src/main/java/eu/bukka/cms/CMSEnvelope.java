package eu.bukka.cms;

import eu.bukka.options.CMSEnvelopeOptions;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.bc.BcCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
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

    private RecipientInfoGenerator getKEKRecipientInfoGenerator() {
        return new JceKEKRecipientInfoGenerator(getSecretKeyId(), getSecretKey())
                .setProvider("BC");
    }

    public void encrypt() throws IOException, CMSException {
        RecipientInfoGenerator recipientInfoGenerator;
        if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            // KEKRecipientInfo choice
            recipientInfoGenerator = getKEKRecipientInfoGenerator();
        } else {
            throw new CMSException("No recipient info");
        }

        byte[] encodedData;
        CMSTypedData data = new CMSProcessableByteArray(getInputData());
        Algorithm algorithm = getAlgorithm();
        if (algorithm.isAuthenticated()) {
            OutputEncryptor encryptor = new BcCMSContentEncryptorBuilder(algorithm.getIdentifier()).build();
            CMSAuthEnvelopedDataGenerator authEnvDataGenerator = new CMSAuthEnvelopedDataGenerator();
            authEnvDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);
            CMSAuthEnvelopedData authEnvData = authEnvDataGenerator.generate(data, (OutputAEADEncryptor)encryptor);
            //TODO: wait for support for getting encoded data - this currently doesn't work.
            // encodedData = authEnvData.getEncoded();
            throw new CMSException("It is not possible encode auth enveloped data");
        } else {
            OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(algorithm.getIdentifier())
                    .setProvider("BC").build();
            CMSEnvelopedDataGenerator envDataGenerator = new CMSEnvelopedDataGenerator();
            envDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);
            CMSEnvelopedData envData = envDataGenerator.generate(data, encryptor);
            encodedData = envData.getEncoded();
        }
        if (getForm() == Form.PEM) {
            ContentInfo ci = ContentInfo.getInstance(ASN1Sequence.fromByteArray(encodedData));
            JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(options.getOutputFile()));
            writer.writeObject(ci);
            writer.close();
        } else {
            FileUtils.writeByteArrayToFile(options.getOutputFile(), encodedData);
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
