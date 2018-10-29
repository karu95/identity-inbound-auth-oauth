package org.wso2.carbon.identity.oauth2.util.cryptoutil;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWECryptoParts;
import com.nimbusds.jose.JWEEncrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.crypto.api.HybridEncryptionInput;
import org.wso2.carbon.crypto.api.HybridEncryptionOutput;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.Charset;
import java.util.Set;

public class CryptoServiceBasedRSAEncrypter implements JWEEncrypter {

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    public CryptoServiceBasedRSAEncrypter(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (OAuth2ServiceComponentHolder.getCryptoService() != null) {
            cryptoService = OAuth2ServiceComponentHolder.getCryptoService();
        }
    }

    @Override
    public JWECryptoParts encrypt(JWEHeader jweHeader, byte[] clearText) throws JOSEException {

        String symmetricAlgorithm = CipherHelper.resolveSymmetricAlgorithm(jweHeader.getEncryptionMethod());
        String asymmetricAlgorithm = CipherHelper.resolveAsymmetricAlgorithm(jweHeader.getAlgorithm());

        HybridEncryptionOutput encryptionOutput;
        try {
            if (symmetricAlgorithm.contains("GCM")) {
                encryptionOutput = cryptoService.hybridEncrypt(new HybridEncryptionInput(clearText,
                        computeAAD(jweHeader)), symmetricAlgorithm, asymmetricAlgorithm, jceProvider, cryptoContext);
            } else {
                String errorMessage = "";
                throw new JOSEException(errorMessage);
            }
        } catch (CryptoException e) {
            String errorMessage = "";
            throw new JOSEException(errorMessage, e);
        }

        Base64URL encryptedKey = Base64URL.encode(encryptionOutput.getEncryptedSymmetricKey());
        Base64URL iv;

        if (encryptionOutput.getParameterSpec() instanceof GCMParameterSpec) {
            iv = Base64URL.encode(((GCMParameterSpec) encryptionOutput.getParameterSpec()).getIV());
        } else {
            String errorMessage = "";
            throw new JOSEException(errorMessage);
        }

        Base64URL authTag = Base64URL.encode(encryptionOutput.getAuthTag());
        Base64URL cipherText = Base64URL.encode(encryptionOutput.getCipherData());

        return new JWECryptoParts(jweHeader,
                encryptedKey,
                iv,
                cipherText,
                authTag);
    }

    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {
        return CipherHelper.getSupportedAlgorithms();
    }

    @Override
    public Set<EncryptionMethod> supportedEncryptionMethods() {
        return CipherHelper.getSupportedEncryptionMethods();
    }

    @Override
    public JWEJCAContext getJCAContext() {
        return null;
    }

    private byte[] computeAAD(JWEHeader header) {

        return header.toBase64URL().toString().getBytes(Charset.forName("ASCII"));
    }
}
