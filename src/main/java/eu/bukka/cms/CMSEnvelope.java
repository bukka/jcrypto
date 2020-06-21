package eu.bukka.cms;

import eu.bukka.cms.options.CMSEnvelopedDataOptions;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;

import java.io.IOException;

public class CMSEnvelope extends CMSData {
    public CMSEnvelope(CMSEnvelopedDataOptions options) {
        super(options);
    }

    public void encrypt() throws IOException, CMSException {
        CMSEnvelopedDataGenerator envGen = new CMSEnvelopedDataGenerator();
        CMSEnvelopedData envData = envGen.generate(
            new CMSProcessableByteArray(getMessage()),
            new JceCMSContentEncryptorBuilder(getAlgorithm()).setProvider("BC").build());
    }
}
