package kz.gov.egg.sync.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Collectors;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSPasswordCallback;

import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.pkcs.PKCSObjectIdentifiers;
import kz.gov.pki.kalkan.xmldsig.DsigConstants;
import lombok.Getter;

@Getter
public class SignConfig {

    private static final String PROVIDER = "KALKAN";
    private final String keystoreFile;
    private final char[] keystorePassword;
    private final String truststoreFile;
    private final char[] truststorePassword;
    private final String crlFiles;
    private final String alias;
    private final X509Certificate certificate;
    private final Properties merlinProperties;
    private final Map<String, Object> outInterceptorProperties;
    private final Map<String, Object> inInterceptorProperties;

    public SignConfig(String keystoreFile, char[] keystorePassword, String truststoreFile, char[] truststorePassword,
            String crlDirectory) {
        try {
            var keyStore = KeyStore.getInstance("PKCS12", PROVIDER);
            keyStore.load(new FileInputStream(keystoreFile), keystorePassword);
            Enumeration<String> aliases = keyStore.aliases();
            if (!aliases.hasMoreElements()) {
                throw new IllegalArgumentException("No key alias found");
            }
            alias = aliases.nextElement();
            certificate = (X509Certificate) keyStore.getCertificate(alias);
            this.keystorePassword = keystorePassword;
            this.keystoreFile = keystoreFile;
            this.truststoreFile = truststoreFile;
            this.truststorePassword = truststorePassword;
            if (crlDirectory != null) {
                crlFiles = Files.list(Paths.get(crlDirectory)).map(e -> e.toString()).filter(e -> e.endsWith(".crl"))
                        .collect(Collectors.joining(","));
            } else {
                crlFiles = null;
            }
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException
                | IOException e) {
            throw new IllegalStateException("KeyStore not loaded.", e);
        }

        String signatureAlgorithm;
        String digestAlgorithm;

        var sigAlgOid = certificate.getSigAlgOID();

        if (sigAlgOid.equals(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId())) {
            signatureAlgorithm = DsigConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
            digestAlgorithm = DsigConstants.ALGO_ID_DIGEST_SHA256;
        } else if (sigAlgOid.equals(KNCAObjectIdentifiers.gost34311_95_with_gost34310_2004.getId())) {
            signatureAlgorithm = DsigConstants.ALGO_ID_SIGNATURE_ECGOST34310_2004_ECGOST34311_95;
            digestAlgorithm = DsigConstants.ALGO_ID_DIGEST_ECGOST34311_95;
        } else if (sigAlgOid.equals(KNCAObjectIdentifiers.gost3411_2015_with_gost3410_2015_512.getId())) {
            signatureAlgorithm = DsigConstants.ALGO_ID_SIGNATURE_ECGOST3410_2015_ECGOST3411_2015_512;
            digestAlgorithm = DsigConstants.ALGO_ID_DIGEST_ECGOST3411_2015_512;
        } else {
            throw new IllegalArgumentException("Unsupported sigAlgOid: " + sigAlgOid);
        }

        merlinProperties = new Properties();
        merlinProperties.put(Merlin.PREFIX + Merlin.CRYPTO_KEYSTORE_PROVIDER, PROVIDER);
        merlinProperties.put(Merlin.PREFIX + Merlin.CRYPTO_CERT_PROVIDER, PROVIDER);
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_TYPE, "PKCS12");
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_PASSWORD, new String(keystorePassword));
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_ALIAS, alias);
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_FILE, keystoreFile);
        merlinProperties.put(Merlin.PREFIX + Merlin.TRUSTSTORE_PROVIDER, PROVIDER);
        merlinProperties.put(Merlin.PREFIX + Merlin.TRUSTSTORE_TYPE, "JKS");
        merlinProperties.put(Merlin.PREFIX + Merlin.TRUSTSTORE_FILE, truststoreFile);
        merlinProperties.put(Merlin.PREFIX + Merlin.TRUSTSTORE_PASSWORD, new String(truststorePassword));

        outInterceptorProperties = new HashMap<>();
        outInterceptorProperties.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        outInterceptorProperties.put(ConfigurationConstants.ADD_INCLUSIVE_PREFIXES, "false");
        outInterceptorProperties.put("signingProperties", merlinProperties);
        outInterceptorProperties.put(ConfigurationConstants.SIG_PROP_REF_ID, "signingProperties");
        outInterceptorProperties.put(ConfigurationConstants.USER, alias);
        outInterceptorProperties.put(ConfigurationConstants.PW_CALLBACK_REF, obtainPasswordCallback());
        outInterceptorProperties.put(ConfigurationConstants.SIG_ALGO, signatureAlgorithm);
        outInterceptorProperties.put(ConfigurationConstants.SIG_DIGEST_ALGO, digestAlgorithm);

        inInterceptorProperties = new HashMap<>();
        inInterceptorProperties.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        inInterceptorProperties.put("verifyProperties", merlinProperties);
        inInterceptorProperties.put(ConfigurationConstants.SIG_VER_PROP_REF_ID, "verifyProperties");
        if (crlFiles != null) {
            merlinProperties.put(Merlin.PREFIX + Merlin.X509_CRL_FILE, crlFiles);
            inInterceptorProperties.put(ConfigurationConstants.ENABLE_REVOCATION, "true");
        }
    }
    
    public SignConfig(String keystoreFile, char[] keystorePassword, String truststoreFile, char[] truststorePassword) {
        this(keystoreFile, keystorePassword, truststoreFile, truststorePassword, null);
    }

    private CallbackHandler obtainPasswordCallback() {
        return callbacks -> {
            WSPasswordCallback callback = (WSPasswordCallback) callbacks[0];
            callback.setPassword(new String(keystorePassword));
        };
    }

}
