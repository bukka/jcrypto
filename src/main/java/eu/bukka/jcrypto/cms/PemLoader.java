package eu.bukka.jcrypto.cms;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Loads X.509 certificates and private keys from PEM files. Shared by the CMS enveloping and
 * signing paths so neither depends on the other's options.
 */
public final class PemLoader {
    private PemLoader() {
    }

    public static X509Certificate loadCertificate(File certificateFile) throws CMSException {
        try (FileReader certReader = new FileReader(certificateFile);
             PEMParser pemParser = new PEMParser(certReader)) {

            Object object = pemParser.readObject();
            if (object instanceof X509CertificateHolder) {
                return new JcaX509CertificateConverter().setProvider("BC")
                        .getCertificate((X509CertificateHolder) object);
            } else if (object instanceof Certificate) {
                return (X509Certificate) object;
            } else {
                throw new CMSException("Invalid certificate format");
            }
        } catch (IOException e) {
            throw new CMSException("Failed to load certificate", e);
        } catch (CertificateException e) {
            throw new CMSException("Failed to parse certificate", e);
        }
    }

    public static PrivateKey loadPrivateKey(File privateKeyFile) throws CMSException {
        try (FileReader keyReader = new FileReader(privateKeyFile);
             PEMParser pemParser = new PEMParser(keyReader)) {

            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                PKCS8EncryptedPrivateKeyInfo encryptedPrivateKeyInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                // TODO: handle a decryption password if the key is encrypted.
                PrivateKeyInfo privateKeyInfo = encryptedPrivateKeyInfo.decryptPrivateKeyInfo(null);
                return converter.getPrivateKey(privateKeyInfo);
            } else if (object instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) object);
            } else if (object instanceof PEMKeyPair) {
                KeyPair kp = converter.getKeyPair((PEMKeyPair) object);
                return kp.getPrivate();
            } else {
                throw new CMSException("Invalid private key format");
            }
        } catch (IOException e) {
            throw new CMSException("Failed to load private key", e);
        } catch (PKCSException e) {
            throw new RuntimeException(e);
        }
    }
}
