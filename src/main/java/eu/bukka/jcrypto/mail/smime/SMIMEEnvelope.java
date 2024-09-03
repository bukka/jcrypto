package eu.bukka.jcrypto.mail.smime;

import eu.bukka.jcrypto.cms.RecipientHandler;
import eu.bukka.jcrypto.cms.RecipientInfoGeneratorFactory;
import eu.bukka.jcrypto.bc.mail.smime.SMIMEAuthEnveloped;
import eu.bukka.jcrypto.bc.mail.smime.SMIMEAuthEnvelopedGenerator;
import eu.bukka.jcrypto.bc.mail.smime.SMIMEAuthEnvelopedParser;
import eu.bukka.jcrypto.options.MailSMIMEEnvelopeOptions;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.mail.smime.*;
import org.bouncycastle.operator.OutputEncryptor;

import javax.activation.CommandMap;
import javax.activation.DataHandler;
import javax.activation.MailcapCommandMap;
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

    public class NoHeaderMimeMessage extends MimeMessage {
        public NoHeaderMimeMessage(Session session) {
            super(session);
        }

        @Override
        protected void updateMessageID() throws MessagingException {
            // no Message-ID header
        }

        @Override
        protected void updateHeaders() throws MessagingException {
            // no header update
        }

        @Override
        public void saveChanges() throws MessagingException {
            // to not add extra headers potentially
        }

        @Override
        public String getContentType() {
            return null; // prevent Content-Type header
        }

        @Override
        public String getEncoding() {
            return null; // prevent Content-Transfer-Encoding header
        }
    }

    private MimeBodyPart generateBodyPart(MimeBodyPart bodyPart) throws CMSException, SMIMEException, MessagingException {
        SMIMEData.Algorithm algorithm = getAlgorithm();
        OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(algorithm.getIdentifier())
                .setProvider("BC").build();
        RecipientInfoGenerator recipientInfoGenerator = recipientInfoGeneratorFactory.create();

        MimeMessage msg = new NoHeaderMimeMessage(null);
        DataHandler dataHandler = bodyPart.getDataHandler();
        MailcapCommandMap mc = (MailcapCommandMap) CommandMap.getDefaultCommandMap();
        mc.addMailcap("text/html;; x-java-content-handler=com.sun.mail.handlers.text_html");
        mc.addMailcap("text/xml;; x-java-content-handler=com.sun.mail.handlers.text_xml");
        mc.addMailcap("text/plain;; x-java-content-handler=com.sun.mail.handlers.text_plain");
        mc.addMailcap("multipart/*;; x-java-content-handler=com.sun.mail.handlers.multipart_mixed");
        mc.addMailcap("message/rfc822;; x-java-content-handler=com.sun.mail.handlers.message_rfc822");
        dataHandler.setCommandMap(mc);
        msg.setDataHandler(bodyPart.getDataHandler());
        msg.saveChanges();

        if (algorithm.isAuthenticated()) {
            SMIMEAuthEnvelopedGenerator authEnvDataGenerator = new SMIMEAuthEnvelopedGenerator();
            authEnvDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);
            return authEnvDataGenerator.generate(msg, encryptor);
        } else {
            SMIMEEnvelopedGenerator authEnvDataGenerator = new SMIMEEnvelopedGenerator();
            authEnvDataGenerator.addRecipientInfoGenerator(recipientInfoGenerator);
            return authEnvDataGenerator.generate(msg, encryptor);
        }
    }

    public void encrypt() throws IOException, CMSException, MessagingException, SMIMEException {
        // Get a Session object and create the mail message
        Properties props = System.getProperties();
        Session session = Session.getDefaultInstance(props, null);

        Address fromUser = new InternetAddress(options.getMailFrom());
        Address toUser = new InternetAddress(options.getMailTo());

        MimeMessage body = new MimeMessage(session);
        body.setFrom(fromUser);
        body.setRecipient(Message.RecipientType.TO, toUser);
        body.setSubject(options.getMailSubject());

        MimeBodyPart msg = createMimeBodyPart();
        MimeBodyPart mp = generateBodyPart(msg);

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
