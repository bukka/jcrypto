package eu.bukka.jcrypto.options;

public interface MailSMIMEEnvelopeOptions extends CMSEnvelopeOptions {
    String getMailTo();

    String getMailFrom();

    String getMailSubject();

    String getMimeType();

    String getCharset();
}
