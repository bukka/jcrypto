package eu.bukka.cms;

import eu.bukka.cms.options.CMSEnvelopeOptions;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
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

    public void encrypt() throws IOException, CMSException {
        CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();
        if (options.getSecretKey() != null && options.getSecretKeyIdentifier() != null) {
            // KEKRecipientInfo choice
            byte[] keyID = Strings.toByteArray(options.getSecretKeyIdentifier());
            SecretKey wrappingKey = new SecretKeySpec(Hex.decode(options.getSecretKey()), "AES");
            envGen.addRecipientInfoGenerator(
                    new JceKEKRecipientInfoGenerator(keyID, wrappingKey).setProvider("BC"));
        }
        CMSEnvelopedData envData = envGen.generate(
            new CMSProcessableByteArray(getMessage()),
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
}
