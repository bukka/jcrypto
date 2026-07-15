package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CommonOptions;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemObject;

import java.io.ByteArrayInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidParameterException;

/**
 * Shared form-based IO for CMS operations: reads the {@code --form} option and writes/reads the
 * PEM or DER encoding. Parameterised on the operation's options so enveloping and signing can share
 * this without sharing each other's recipient/signer concerns.
 */
abstract public class CMSContent<T extends CommonOptions> {
    protected final T options;

    protected enum Form {
        DER,
        PEM,
    }

    protected CMSContent(T options) {
        this.options = options;
    }

    protected Form getForm() {
        String form = options.getForm();
        switch (form) {
            case "BER": // We treat BER as DER for now
            case "DER":
                return Form.DER;
            case "PEM":
                return Form.PEM;
            default:
                throw new InvalidParameterException("Invalid form " + form);
        }
    }

    protected void writeEncoded(byte[] encodedData) throws IOException {
        if (getForm() == Form.PEM) {
            // Use the "CMS" PEM label to match OpenSSL; BouncyCastle would otherwise write "PKCS7".
            try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(options.getOutputFile()))) {
                writer.writeObject(new PemObject("CMS", encodedData));
            }
        } else {
            options.writeOutputData(encodedData);
        }
    }

    protected byte[] convertPemToBer(byte[] pemData) throws IOException {
        try (PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream(pemData)))) {
            PemObject pemObject = pemParser.readPemObject();
            if (pemObject == null) {
                throw new IOException("Invalid PEM data");
            }
            return pemObject.getContent();
        }
    }
}
