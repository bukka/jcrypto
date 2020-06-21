package eu.bukka.cms;

import eu.bukka.cms.options.CMSEnvelopedDataOptions;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;

import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidParameterException;

abstract public class CMSData {
    protected CMSEnvelopedDataOptions options;

    public CMSData(CMSEnvelopedDataOptions options) {
        this.options = options;
    }

    protected byte[] getMessage() throws IOException {
        return Files.readAllBytes(options.getInputFile().toPath());
    }

    protected ASN1ObjectIdentifier getAlgorithm() {
        switch (options.getAlgorithm().toUpperCase()) {
            case "AES128_GCM":
            case "AES-128-GCM":
                return CMSAlgorithm.AES128_GCM;
            case "AES256_GCM":
            case "AES-256-GCM":
                return CMSAlgorithm.AES256_GCM;
            case "AES128_CBC":
            case "AES-128-CBC":
                return CMSAlgorithm.AES128_CBC;
            case "AES256_CBC":
            case "AES-256-CBC":
                return CMSAlgorithm.AES256_CBC;
            default:
                throw new InvalidParameterException("Invalid algorithm");
        }
    }
}
