package eu.bukka.jcrypto.mail.smime;

import eu.bukka.jcrypto.cms.RecipientHandler;
import eu.bukka.jcrypto.cms.RecipientInfoGeneratorFactory;
import eu.bukka.jcrypto.mail.smime.bc.SMIMEAuthEnveloped;
import eu.bukka.jcrypto.mail.smime.bc.SMIMEAuthEnvelopedGenerator;
import eu.bukka.jcrypto.options.MailSMIMEEnvelopeOptions;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEKEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEKRecipientInfoGenerator;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.mail.Address;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import java.io.*;
import java.util.Properties;

public class SMIMEEnvelope extends SMIMEData {
    public SMIMEEnvelope(MailSMIMEEnvelopeOptions options, RecipientInfoGeneratorFactory recipientInfoGeneratorFactory,
                         RecipientHandler recipientHandler) {
        super(options, recipientInfoGeneratorFactory, recipientHandler);
    }

    public void encrypt() throws IOException, CMSException, MessagingException, SMIMEException {
        RecipientInfoGenerator recipientInfoGenerator = recipientInfoGeneratorFactory.create();

        MimeBodyPart msg = new MimeBodyPart();
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
        body.setContent(mp.getContent(), mp.getContentType());
        body.saveChanges();
        body.writeTo(options.getOutputStream());
    }

    private RecipientInformationStore getDataRecipients(MimeMessage msg) throws IOException, CMSException, MessagingException {
        SMIMEData.Algorithm algorithm = getAlgorithm();
        if (algorithm.isAuthenticated()) {
            CMSAuthEnvelopedData authEnvelopedData = new SMIMEAuthEnveloped(msg);
            return authEnvelopedData.getRecipientInfos();
        } else {
            CMSEnvelopedData envelopedData = new SMIMEEnveloped(msg);
            return envelopedData.getRecipientInfos();
        }
    }

    public void decrypt() throws IOException, CMSException, MessagingException {
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        MimeMessage msg = new MimeMessage(session, new ByteArrayInputStream(options.getInputData()));

        RecipientInformationStore recipients = getDataRecipients(msg);
        byte[] decryptedData = recipientHandler.getContent(recipients);
        options.writeOutputData(decryptedData);
    }
}
