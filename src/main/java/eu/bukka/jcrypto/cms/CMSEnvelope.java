package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
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
    public CMSEnvelope(CMSEnvelopeOptions options, RecipientInfoGeneratorFactory recipientInfoGeneratorFactory,
                       RecipientHandler recipientHandler) {
        super(options, recipientInfoGeneratorFactory, recipientHandler);
    }

    public CMSEnvelope(CMSEnvelopeOptions options) {
        this(options, new RecipientInfoGeneratorFactory(options), new RecipientHandler(options));
    }

    public void encrypt() throws IOException, CMSException {
        RecipientInfoGenerator recipientInfoGenerator = recipientInfoGeneratorFactory.create();

        byte[] encodedData;
        CMSTypedData data = new CMSProcessableByteArray(options.getInputData());
        Algorithm algorithm = getAlgorithm();
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(algorithm.getIdentifier())
                .setProvider("BC").build();
        if (algorithm.isAuthenticated()) {
            CMSAuthEnvelopedDataGenerator authEnvDataGenerator = new CMSAuthEnvelopedDataGenerator();
            authEnvDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);
            CMSAuthEnvelopedData authEnvData = authEnvDataGenerator.generate(data, (OutputAEADEncryptor) encryptor);
            encodedData = authEnvData.getEncoded();
        } else {
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
            options.writeOutputData(encodedData);
        }
    }

    private RecipientInformationStore getDataRecipients() throws IOException, CMSException {
        Algorithm algorithm = getAlgorithm();
        if (algorithm.isAuthenticated()) {
            CMSAuthEnvelopedData authEnvelopedData = new CMSAuthEnvelopedData(options.getInputData());
            return authEnvelopedData.getRecipientInfos();
        } else {
            CMSEnvelopedData envelopedData = new CMSEnvelopedData(options.getInputData());
            return envelopedData.getRecipientInfos();
        }
    }

    public void decrypt() throws IOException, CMSException {
        RecipientInformationStore recipients = getDataRecipients();
        byte[] decryptedData = recipientHandler.getContent(recipients);
        if (getForm() == Form.PEM) {
            JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(options.getOutputFile()));
            writer.write(Strings.fromByteArray(decryptedData));
            writer.close();
        } else {
            options.writeOutputData(decryptedData);
        }
    }
}
