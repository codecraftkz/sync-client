package kz.gov.egg.sync.client;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.ConfigurationConstants;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSPasswordCallback;

import kz.gov.pki.kalkan.xmldsig.DsigConstants;
import lombok.Getter;

@Getter
public class SignConfig {

    private static final String PROVIDER = "KALKAN";
    private final String keystoreFile;
    private final char[] keystorePassword;
    private final String alias;
    private final Properties merlinProperties;
    private final Map<String, Object> outInterceptorProperties;

    public SignConfig(String keystoreFile, char[] keystorePassword) {
        try {
            var keyStore = KeyStore.getInstance("PKCS12", PROVIDER);
            keyStore.load(new FileInputStream(keystoreFile), keystorePassword);
            Enumeration<String> aliases = keyStore.aliases();
            if (!aliases.hasMoreElements()) {
                throw new IllegalArgumentException("No key alias found");
            }
            alias = aliases.nextElement();
            this.keystorePassword = keystorePassword;
            this.keystoreFile = keystoreFile;
        } catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException
                | IOException e) {
            throw new IllegalStateException("KeyStore not loaded.", e);
        }
        
        //TODO: verify certificate

        merlinProperties = new Properties();
        merlinProperties.put(Merlin.PREFIX + Merlin.CRYPTO_KEYSTORE_PROVIDER, PROVIDER);
        merlinProperties.put(Merlin.PREFIX + Merlin.CRYPTO_CERT_PROVIDER, PROVIDER);
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_TYPE, "PKCS12");
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_PASSWORD, new String(keystorePassword));
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_ALIAS, alias);
        merlinProperties.put(Merlin.PREFIX + Merlin.KEYSTORE_FILE, keystoreFile);

        outInterceptorProperties = new HashMap<>();
        outInterceptorProperties.put(ConfigurationConstants.ACTION, ConfigurationConstants.SIGNATURE);
        outInterceptorProperties.put(ConfigurationConstants.ADD_INCLUSIVE_PREFIXES, "false");
        outInterceptorProperties.put("signingProperties", merlinProperties);
        outInterceptorProperties.put(ConfigurationConstants.SIG_PROP_REF_ID, "signingProperties");
        outInterceptorProperties.put(ConfigurationConstants.USER, alias);
        outInterceptorProperties.put(ConfigurationConstants.PW_CALLBACK_REF, obtainPasswordCallback());
        outInterceptorProperties.put(ConfigurationConstants.SIG_ALGO,
                DsigConstants.ALGO_ID_SIGNATURE_ECGOST34310_2004_ECGOST34311_95);
        outInterceptorProperties.put(ConfigurationConstants.SIG_DIGEST_ALGO,
                DsigConstants.ALGO_ID_DIGEST_ECGOST34311_95);
    }

    private CallbackHandler obtainPasswordCallback() {
        return callbacks -> {
            WSPasswordCallback callback = (WSPasswordCallback) callbacks[0];
            callback.setPassword(new String(keystorePassword));
        };
    }

}
