package org.wso2.carbon.identity.oauth2.util.cryptoutil;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.jca.JWEJCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.crypto.api.HybridEncryptionOutput;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.Charset;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Set;

public class CryptoServiceBasedRSADecrypter implements JWEDecrypter {

    private CryptoContext cryptoContext;
    private String jceProvider;
    private CryptoService cryptoService;

    public CryptoServiceBasedRSADecrypter(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (OAuth2ServiceComponentHolder.getCryptoService() != null) {
            cryptoService = OAuth2ServiceComponentHolder.getCryptoService();
        }
    }

    @Override
    public byte[] decrypt(JWEHeader jweHeader, Base64URL encryptedKey, Base64URL iv, Base64URL cipherText,
                          Base64URL authTag) throws JOSEException {

        if (encryptedKey == null) {
            throw new JOSEException("Missing JWE encrypted key");
        }

        if (iv == null) {
            throw new JOSEException("Missing JWE initialization vector (IV)");
        }

        if (authTag == null) {
            throw new JOSEException("Missing JWE authentication tag");
        }

        String asymmetricAlgorithm = CipherHelper.resolveAsymmetricAlgorithm(jweHeader.getAlgorithm());
        String symmetricAlgorithm = CipherHelper.resolveSymmetricAlgorithm(jweHeader.getEncryptionMethod());

        AlgorithmParameterSpec parameterSpec;
        if (symmetricAlgorithm.contains("GCM")) {
            parameterSpec = new GCMParameterSpec(128, iv.decode());
        } else {
            String errorMessage = String.format("Symmetric algorithm '%s' is not supported by '%s'",
                    symmetricAlgorithm, this.getClass().getName());
            throw new JOSEException(errorMessage);
        }

        byte[] aad = computeAAD(jweHeader);

        try {
            return cryptoService.hybridDecrypt(new HybridEncryptionOutput(cipherText.decode(), encryptedKey.decode(),
                    aad, authTag.decode(), parameterSpec), symmetricAlgorithm, asymmetricAlgorithm, jceProvider, cryptoContext);
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while hybrid decrypting JWT using " +
                    "symmetric algorithm '%s' and asymmetric algorithm '%s'.", symmetricAlgorithm, asymmetricAlgorithm);
            throw new JOSEException(errorMessage, e);
        }
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
