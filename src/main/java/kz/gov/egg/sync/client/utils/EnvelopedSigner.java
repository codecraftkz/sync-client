package kz.gov.egg.sync.client.utils;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import kz.gov.egg.sync.client.SignConfig;
import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.xmldsig.DsigConstants;

public class EnvelopedSigner {

    private PrivateKey key;
    private X509Certificate cert;

    public EnvelopedSigner(SignConfig signConfig) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12", "KALKAN");
            keyStore.load(new FileInputStream(signConfig.getKeystoreFile()), signConfig.getKeystorePassword());
            key = (PrivateKey) keyStore.getKey(signConfig.getAlias(), signConfig.getKeystorePassword());
            cert = (X509Certificate) keyStore.getCertificate(signConfig.getAlias());
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException
                | IOException | UnrecoverableKeyException e) {
            throw new IllegalArgumentException("EnvelopedSigner not configured.", e);
        }
    }

    private Document parse(String xml) throws ParserConfigurationException, SAXException, IOException {
        var dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setNamespaceAware(true);
        var documentBuilder = dbf.newDocumentBuilder();
        var document = documentBuilder.parse(new ByteArrayInputStream(xml.getBytes()));
        return document;
    }

    public String sign(String xml) {
        try (var os = new StringWriter()) {
            var document = parse(xml);
            String signMethod;
            String digestMethod;

            var sigAlgOid = cert.getSigAlgOID();
            if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
                signMethod = DsigConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
                digestMethod = DsigConstants.ALGO_ID_DIGEST_SHA256;
            } else if (sigAlgOid.equals(KNCAObjectIdentifiers.gost34311_95_with_gost34310_2004.getId())) {
                signMethod = DsigConstants.ALGO_ID_SIGNATURE_ECGOST34310_2004_ECGOST34311_95;
                digestMethod = DsigConstants.ALGO_ID_DIGEST_ECGOST34311_95;
            } else if (sigAlgOid.equals(KNCAObjectIdentifiers.gost3411_2015_with_gost3410_2015_512.getId())) {
                signMethod = DsigConstants.ALGO_ID_SIGNATURE_ECGOST3410_2015_ECGOST3411_2015_512;
                digestMethod = DsigConstants.ALGO_ID_DIGEST_ECGOST3411_2015_512;
            } else {
                throw new IllegalArgumentException("Incorrect algorithm: " + sigAlgOid);
            }

            var transforms = new Transforms(document);
            transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
            transforms.addTransform(Transforms.TRANSFORM_C14N_WITH_COMMENTS);
            var xmlSignature = new XMLSignature(document, "", signMethod);
            document.getFirstChild().appendChild(xmlSignature.getElement());
            xmlSignature.addDocument("", transforms, digestMethod);
            xmlSignature.addKeyInfo(cert);
            xmlSignature.sign(key);

            return EggUtils.nodeToString(document.getFirstChild());
        } catch (IOException | ParserConfigurationException | SAXException | XMLSecurityException e) {
            throw new IllegalStateException("Enveloped xml signature failed.", e);
        }
    }

    public boolean verify(String xml) {
        try {
            var doc = parse(xml);
            var rootEl = (Element) doc.getFirstChild();
            var list = rootEl.getElementsByTagName("ds:Signature");
            if (list.getLength() == 0) {
                throw new IllegalStateException("ds:Signature not found");
            }
            var sigNode = list.item(0);
            var sigElement = (Element) sigNode;
            XMLSignature signature = new XMLSignature(sigElement, "");
            var keyInfo = signature.getKeyInfo();
            X509Certificate cert = keyInfo.getX509Certificate();
            if (cert == null) {
                throw new IllegalStateException("Certificate not found in XML");
            }
            return signature.checkSignatureValue(cert);
        } catch (IOException | ParserConfigurationException | SAXException | XMLSecurityException e) {
            throw new RuntimeException("Enveloped xml verification failed.", e);
        }
    }

}
