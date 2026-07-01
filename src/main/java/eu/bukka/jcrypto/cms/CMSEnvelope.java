package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSEnvelopeOptions;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceCMSMacCalculatorBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OutputAEADEncryptor;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.*;
import java.security.InvalidParameterException;
import java.util.Map;

public class CMSEnvelope extends CMSData {
    private CMSStructure structure;

    public CMSEnvelope(CMSEnvelopeOptions options, RecipientInfoGeneratorFactory recipientInfoGeneratorFactory,
                       RecipientHandler recipientHandler) {
        super(options, recipientInfoGeneratorFactory, recipientHandler);
        structure = resolveStructure();
    }

    public CMSEnvelope(CMSEnvelopeOptions options) {
        super(options);
        structure = resolveStructure();
    }

    private CMSStructure resolveStructure() {
        String contentType = options.getContentType();
        if ("authenticated-data".equals(contentType)) {
            return CMSStructure.AUTHENTICATED;
        }
        if (getAlgorithm().isAuthenticated()
                && (contentType == null || contentType.equals("authEnveloped-data"))) {
            return CMSStructure.AUTH_ENVELOPED;
        }
        return CMSStructure.ENVELOPED;
    }

    public void encrypt() throws IOException, CMSException {
        RecipientInfoGenerator recipientInfoGenerator = recipientInfoGeneratorFactory.create();
        CMSTypedData data = new CMSProcessableByteArray(options.getInputData());

        byte[] encodedData;
        switch (structure) {
            case AUTH_ENVELOPED:
                encodedData = generateAuthEnveloped(recipientInfoGenerator, data);
                break;
            case AUTHENTICATED:
                encodedData = generateAuthenticated(recipientInfoGenerator, data);
                break;
            default:
                encodedData = generateEnveloped(recipientInfoGenerator, data);
        }
        writeEncoded(encodedData);
    }

    private byte[] generateEnveloped(RecipientInfoGenerator recipientInfoGenerator, CMSTypedData data)
            throws IOException, CMSException {
        if (hasAttributes(options.getAuthenticatedAttributes())
                || hasAttributes(options.getUnauthenticatedAttributes())) {
            throw new CMSException("Attributes are only supported for authEnveloped-data and authenticated-data");
        }
        CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
        generator.addRecipientInfoGenerator(recipientInfoGenerator);
        return generator.generate(data, contentEncryptor()).getEncoded();
    }

    private byte[] generateAuthEnveloped(RecipientInfoGenerator recipientInfoGenerator, CMSTypedData data)
            throws IOException, CMSException {
        CMSAuthEnvelopedDataGenerator generator = new CMSAuthEnvelopedDataGenerator();
        generator.addRecipientInfoGenerator(recipientInfoGenerator);
        if (hasAttributes(options.getAuthenticatedAttributes())) {
            generator.setAuthenticatedAttributeGenerator(
                    attributeTableGenerator(options.getAuthenticatedAttributes()));
        }
        if (hasAttributes(options.getUnauthenticatedAttributes())) {
            generator.setUnauthenticatedAttributeGenerator(
                    attributeTableGenerator(options.getUnauthenticatedAttributes()));
        }
        return generator.generate(data, (OutputAEADEncryptor) contentEncryptor()).getEncoded();
    }

    private byte[] generateAuthenticated(RecipientInfoGenerator recipientInfoGenerator, CMSTypedData data)
            throws IOException, CMSException {
        CMSAuthenticatedDataGenerator generator = new CMSAuthenticatedDataGenerator();
        generator.addRecipientInfoGenerator(recipientInfoGenerator);
        if (hasAttributes(options.getAuthenticatedAttributes())) {
            generator.setAuthenticatedAttributeGenerator(
                    attributeTableGenerator(options.getAuthenticatedAttributes()));
        }
        if (hasAttributes(options.getUnauthenticatedAttributes())) {
            generator.setUnauthenticatedAttributeGenerator(
                    attributeTableGenerator(options.getUnauthenticatedAttributes()));
        }
        MacCalculator macCalculator = new JceCMSMacCalculatorBuilder(getMacAlgorithm()).setProvider("BC").build();
        if (hasAttributes(options.getAuthenticatedAttributes())) {
            // Authenticated attributes carry a message-digest of the content that the MAC covers,
            // so a digest calculator is required to build them.
            return generator.generate(data, macCalculator, digestCalculator()).getEncoded();
        }
        return generator.generate(data, macCalculator).getEncoded();
    }

    private OutputEncryptor contentEncryptor() throws CMSException {
        return new JceCMSContentEncryptorBuilder(getAlgorithm().getIdentifier()).setProvider("BC").build();
    }

    private ASN1ObjectIdentifier getMacAlgorithm() {
        String macAlgorithm = options.getMacAlgorithm();
        if (macAlgorithm == null) {
            return PKCSObjectIdentifiers.id_hmacWithSHA256;
        }
        switch (macAlgorithm.toUpperCase().replace("-", "").replace("_", "")) {
            case "HMACSHA1":
            case "SHA1":
                return PKCSObjectIdentifiers.id_hmacWithSHA1;
            case "HMACSHA224":
            case "SHA224":
                return PKCSObjectIdentifiers.id_hmacWithSHA224;
            case "HMACSHA256":
            case "SHA256":
                return PKCSObjectIdentifiers.id_hmacWithSHA256;
            case "HMACSHA384":
            case "SHA384":
                return PKCSObjectIdentifiers.id_hmacWithSHA384;
            case "HMACSHA512":
            case "SHA512":
                return PKCSObjectIdentifiers.id_hmacWithSHA512;
            default:
                throw new InvalidParameterException("Invalid MAC algorithm " + macAlgorithm);
        }
    }

    private void writeEncoded(byte[] encodedData) throws IOException {
        if (getForm() == Form.PEM) {
            ContentInfo contentInfo = ContentInfo.getInstance(ASN1Sequence.fromByteArray(encodedData));
            try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(options.getOutputFile()))) {
                writer.writeObject(contentInfo);
            }
        } else {
            options.writeOutputData(encodedData);
        }
    }

    private static boolean hasAttributes(Map<String, String> attributes) {
        return attributes != null && !attributes.isEmpty();
    }

    private CMSAttributeTableGenerator attributeTableGenerator(Map<String, String> attributes) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            vector.add(new Attribute(new ASN1ObjectIdentifier(attribute.getKey()),
                    new DERSet(new DERUTF8String(attribute.getValue()))));
        }
        return new SimpleAttributeTableGenerator(new AttributeTable(vector));
    }

    private byte[] convertPemToBer(byte[] pemData) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemData)))) {
            PemObject pemObject = pemParser.readPemObject();
            if (pemObject == null) {
                throw new IOException("Invalid PEM data");
            }
            return pemObject.getContent();
        }
    }

    private RecipientInformationStore getDataRecipients(byte[] inputData) throws CMSException {
        switch (structure) {
            case AUTH_ENVELOPED:
                return new CMSAuthEnvelopedData(inputData).getRecipientInfos();
            case AUTHENTICATED:
                return new CMSAuthenticatedData(inputData, digestCalculatorProvider()).getRecipientInfos();
            default:
                return new CMSEnvelopedData(inputData).getRecipientInfos();
        }
    }

    private DigestCalculatorProvider digestCalculatorProvider() throws CMSException {
        try {
            return new JcaDigestCalculatorProviderBuilder().setProvider("BC").build();
        } catch (OperatorCreationException e) {
            throw new CMSException("Failed to create digest calculator provider", e);
        }
    }

    private DigestCalculator digestCalculator() throws CMSException {
        try {
            return digestCalculatorProvider().get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        } catch (OperatorCreationException e) {
            throw new CMSException("Failed to create digest calculator", e);
        }
    }

    public void decrypt() throws IOException, CMSException {
        byte[] inputData = options.getInputData();
        if (getForm() == Form.PEM) {
            inputData = convertPemToBer(inputData);
        }
        RecipientInformationStore recipients = getDataRecipients(inputData);
        byte[] decryptedData = recipientHandler.getContent(recipients, structure);
        if (getForm() == Form.PEM) {
            try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(options.getOutputFile()))) {
                writer.write(Strings.fromByteArray(decryptedData));
            }
        } else {
            options.writeOutputData(decryptedData);
        }
    }
}
