package eu.bukka.jcrypto.options;

public interface MailSMIMEEnvelopeOptions extends CMSEnvelopeOptions {
    public String getMailTo();

    public String getMailFrom();

    public String getMailSubject();

    public String getMimeType();

    public String getCharset();
}
