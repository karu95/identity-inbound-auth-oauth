/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.cryptoutil;

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
import org.wso2.carbon.identity.cryptoutil.internal.CryptoUtilDataHolder;

import java.nio.charset.Charset;
import java.util.Set;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Implementation of {@link JWEEncrypter} based of Carbon Crypto Service.
 * Instances of this class provides JWT encryption using Carbon Crypto Service.
 */
public class CryptoServiceBasedRSAEncrypter implements JWEEncrypter {

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    /**
     * @param cryptoContext : Context related to encryption data.
     * @param jceProvider   : JCE Provider used for encryption.
     */
    public CryptoServiceBasedRSAEncrypter(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (CryptoUtilDataHolder.getCryptoService() != null) {
            cryptoService = CryptoUtilDataHolder.getCryptoService();
        }
    }

    /**
     * Encrypt a given JWT using Carbon Crypto Service. {@link CryptoService}
     *
     * @param jweHeader : JWE Header of the token.
     * @param clearText : Clear data to be encrypted.
     * @return Parts of the encryption. {@link JWECryptoParts}
     * @throws JOSEException
     */
    @Override
    public JWECryptoParts encrypt(JWEHeader jweHeader, byte[] clearText) throws JOSEException {

        String symmetricAlgorithm = CipherHelper.resolveSymmetricAlgorithm(jweHeader.getEncryptionMethod());
        String asymmetricAlgorithm = CipherHelper.resolveAsymmetricAlgorithm(jweHeader.getAlgorithm());
        byte[] plainText = DeflateHelper.applyCompression(jweHeader, clearText);
        HybridEncryptionOutput encryptionOutput;
        try {
            if (symmetricAlgorithm.contains("GCM")) {
                encryptionOutput = cryptoService.hybridEncrypt(new HybridEncryptionInput(plainText,
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

    /**
     * Returns set of asymmetric algorithms {@link JWEAlgorithm} supported by {@link CryptoServiceBasedRSAEncrypter}.
     *
     * @return set of supported {@link JWEAlgorithm}
     */
    @Override
    public Set<JWEAlgorithm> supportedJWEAlgorithms() {

        return CipherHelper.getSupportedAlgorithms();
    }

    /**
     * Returns set of symmetric algorithms {@link EncryptionMethod} supported by {@link CryptoServiceBasedRSAEncrypter}.
     *
     * @return set of {@link EncryptionMethod}
     */
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
