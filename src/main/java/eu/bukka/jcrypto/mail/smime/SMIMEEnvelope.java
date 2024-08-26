package eu.bukka.jcrypto.mail.smime;

import eu.bukka.jcrypto.cms.RecipientHandler;
import eu.bukka.jcrypto.cms.RecipientInfoGeneratorFactory;
import eu.bukka.jcrypto.bc.mail.smime.SMIMEAuthEnveloped;
import eu.bukka.jcrypto.bc.mail.smime.SMIMEAuthEnvelopedGenerator;
import eu.bukka.jcrypto.bc.mail.smime.SMIMEAuthEnvelopedParser;
import eu.bukka.jcrypto.options.MailSMIMEEnvelopeOptions;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEEnvelopedParser;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.operator.OutputEncryptor;

import javax.activation.DataHandler;
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.util.ByteArrayDataSource;
import java.io.*;
import java.util.Properties;

public class SMIMEEnvelope extends SMIMEData {
    public SMIMEEnvelope(MailSMIMEEnvelopeOptions options, RecipientInfoGeneratorFactory recipientInfoGeneratorFactory,
                         RecipientHandler recipientHandler) {
        super(options, recipientInfoGeneratorFactory, recipientHandler);
    }

    public SMIMEEnvelope(MailSMIMEEnvelopeOptions options) {
        super(options);
    }

    private MimeBodyPart createMimeBodyPartFromText(byte[] inputData, String charset) throws MessagingException, UnsupportedEncodingException {
        String textContent = new String(inputData, charset);
        MimeBodyPart msg = new MimeBodyPart();
        msg.setText(textContent, charset);

        return msg;
    }

    private MimeBodyPart createMimeBodyPartFromBinary(byte[] inputData, String mimeType) throws MessagingException {
        MimeBodyPart msg = new MimeBodyPart();
        ByteArrayDataSource dataSource = new ByteArrayDataSource(inputData, mimeType);
        msg.setDataHandler(new DataHandler(dataSource));

        return msg;
    }

    private MimeBodyPart createMimeBodyPart() throws IOException, MessagingException {
        byte[] inputData = options.getInputData();
        String mimeType = options.getMimeType();
        if (mimeType.startsWith("text/")) {
            return createMimeBodyPartFromText(inputData, "UTF-8");
        }
        return createMimeBodyPartFromBinary(inputData, mimeType);
    }

    public void encrypt() throws IOException, CMSException, MessagingException, SMIMEException {
        RecipientInfoGenerator recipientInfoGenerator = recipientInfoGeneratorFactory.create();

        MimeBodyPart msg = createMimeBodyPart();
        MimeBodyPart mp;

        SMIMEData.Algorithm algorithm = getAlgorithm();
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(algorithm.getIdentifier())
                .setProvider("BC").build();
        if (algorithm.isAuthenticated()) {
            SMIMEAuthEnvelopedGenerator authEnvDataGenerator = new SMIMEAuthEnvelopedGenerator();
            authEnvDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);
            mp = authEnvDataGenerator.generate(msg, encryptor);
        } else {
            SMIMEEnvelopedGenerator authEnvDataGenerator = new SMIMEEnvelopedGenerator();
            authEnvDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);
            mp = authEnvDataGenerator.generate(msg, encryptor);
        }

        // Get a Session object and create the mail message
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        Address fromUser = new InternetAddress(options.getMailFrom());
        Address toUser = new InternetAddress(options.getMailTo());

        MimeMessage body = new MimeMessage(session);
        body.setFrom(fromUser);
        body.setRecipient(Message.RecipientType.TO, toUser);
        body.setSubject(options.getMailSubject());
        Object content = mp.getContent();
        String contentType = mp.getContentType();
        body.setContent(content, contentType);
        body.saveChanges();
        body.writeTo(options.getOutputStream());
    }

    private RecipientInformationStore getDataRecipients(MimeMessage msg) throws IOException, CMSException, MessagingException {
        SMIMEData.Algorithm algorithm = getAlgorithm();
        if (options.isStream()) {
            if (algorithm.isAuthenticated()) {
                SMIMEAuthEnvelopedParser authEnvelopedParser = new SMIMEAuthEnvelopedParser(msg);
                return authEnvelopedParser.getRecipientInfos();
            } else {
                SMIMEEnvelopedParser envelopedParser = new SMIMEEnvelopedParser(msg);
                return envelopedParser.getRecipientInfos();
            }
        } else {
            if (algorithm.isAuthenticated()) {
                SMIMEAuthEnveloped authEnvelopedData = new SMIMEAuthEnveloped(msg);
                return authEnvelopedData.getRecipientInfos();
            } else {
                SMIMEEnveloped envelopedData = new SMIMEEnveloped(msg);
                return envelopedData.getRecipientInfos();
            }
        }
    }

    public void decrypt() throws IOException, CMSException, MessagingException {
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        MimeMessage msg = new MimeMessage(session, new ByteArrayInputStream(options.getInputData()));

        RecipientInformationStore recipients = getDataRecipients(msg);
        byte[] decryptedData = recipientHandler.getContent(recipients, getAlgorithm().isAuthenticated());
        options.writeOutputData(decryptedData);
    }
}
