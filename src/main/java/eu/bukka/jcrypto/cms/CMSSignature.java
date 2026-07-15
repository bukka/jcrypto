package eu.bukka.jcrypto.cms;

import eu.bukka.jcrypto.options.CMSSignatureOptions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * RFC 5652 CMS SignedData: sign content with a signer certificate/key and verify a signed structure.
 */
public class CMSSignature extends CMSContent<CMSSignatureOptions> {
    public CMSSignature(CMSSignatureOptions options) {
        super(options);
    }

    public void sign() throws IOException, CMSException {
        X509Certificate signerCertificate = PemLoader.loadCertificate(options.getSignerCertificateFile());
        PrivateKey privateKey = PemLoader.loadPrivateKey(options.getPrivateKeyFile());
        String signatureAlgorithm = SignatureAlgorithm.fromDigest(options.getDigestAlgorithm()).getName(privateKey);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        try {
            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(privateKey);
            generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                    .build(signer, signerCertificate));
            // Embed the signer certificate so a verifier can validate without it out of band.
            generator.addCertificate(new JcaX509CertificateHolder(signerCertificate));
        } catch (OperatorCreationException | CertificateEncodingException e) {
            throw new CMSException("Failed to create signer info", e);
        }

        // encapsulate = !detached: a detached signature does not carry the content.
        CMSSignedData signedData = generator.generate(
                new CMSProcessableByteArray(options.getInputData()), !options.isDetached());
        writeEncoded(signedData.getEncoded());
    }

    public void verify() throws IOException, CMSException {
        CMSSignedData signedData = readSignedData();
        Store<X509CertificateHolder> certificates = signedData.getCertificates();
        for (SignerInformation signer : signedData.getSignerInfos()) {
            if (!verifySigner(signer, certificates)) {
                throw new CMSException("Verification failure");
            }
        }
        // On success, emit the signed content (mirrors OpenSSL `cms -verify`).
        options.writeOutputData(getContent(signedData));
    }

    private CMSSignedData readSignedData() throws IOException, CMSException {
        byte[] inputData = options.getInputData();
        if (getForm() == Form.PEM) {
            inputData = convertPemToBer(inputData);
        }
        if (options.isDetached()) {
            return new CMSSignedData(new CMSProcessableByteArray(getDetachedContent()), inputData);
        }
        return new CMSSignedData(inputData);
    }

    private boolean verifySigner(SignerInformation signer, Store<X509CertificateHolder> certificates)
            throws CMSException {
        try {
            return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC")
                    .build(getSignerCertificate(signer, certificates)));
        } catch (OperatorCreationException | CertificateException e) {
            throw new CMSException("Failed to verify signer info", e);
        }
    }

    private X509CertificateHolder getSignerCertificate(SignerInformation signer,
                                                       Store<X509CertificateHolder> certificates)
            throws CMSException {
        if (options.getSignerCertificateFile() != null) {
            try {
                return new JcaX509CertificateHolder(PemLoader.loadCertificate(options.getSignerCertificateFile()));
            } catch (CertificateEncodingException e) {
                throw new CMSException("Failed to load signer certificate", e);
            }
        }
        Collection<X509CertificateHolder> matches = certificates.getMatches(signer.getSID());
        if (matches.isEmpty()) {
            throw new CMSException("No matching certificate found for signer; provide one with --signer-cert");
        }
        return matches.iterator().next();
    }

    private byte[] getContent(CMSSignedData signedData) throws IOException, CMSException {
        CMSTypedData signedContent = signedData.getSignedContent();
        // Detached signatures carry no content, so fall back to the supplied content.
        return signedContent != null ? (byte[]) signedContent.getContent() : getDetachedContent();
    }

    private byte[] getDetachedContent() throws IOException, CMSException {
        if (options.getContentFile() == null) {
            throw new CMSException("--content is required to verify a detached signature");
        }
        return Files.readAllBytes(options.getContentFile().toPath());
    }
}
