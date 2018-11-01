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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.identity.cryptoutil.internal.CryptoUtilDataHolder;

import java.util.Set;

/**
 * Implementation of {@link JWSSigner} based on Carbon Crypto Service.
 * Instances of this class provides JWT signing using Carbon Crypto Service.
 */
public class CryptoServiceBasedRSASigner implements JWSSigner {

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    /**
     * @param cryptoContext : Context related to data to be signed.
     * @param jceProvider   : JCE Provider used for signing.
     */
    public CryptoServiceBasedRSASigner(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (CryptoUtilDataHolder.getCryptoService() != null) {
            cryptoService = CryptoUtilDataHolder.getCryptoService();
        }
    }

    /**
     * Sign a given data related to JWT using  Carbon Crypto Service {@link CryptoService}.
     *
     * @param jwsHeader      : Header of the JWT.
     * @param dataToBeSigned : Data that needs to be signed.
     * @return
     * @throws JOSEException
     */
    @Override
    public Base64URL sign(JWSHeader jwsHeader, byte[] dataToBeSigned) throws JOSEException {

        String algorithm = CryptoServiceBasedRSASSA.getSignVerifyAlgorithm(jwsHeader.getAlgorithm());

        try {
            return Base64URL.encode(cryptoService.sign(dataToBeSigned, algorithm, jceProvider, cryptoContext));
        } catch (CryptoException e) {
            String errorMessage = "";
            throw new JOSEException(errorMessage, e);
        }
    }

    /**
     * Returns set of supported {@link JWSAlgorithm}
     *
     * @return
     */
    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {

        return CryptoServiceBasedRSASSA.getSupportedAlgorithms();
    }

    @Override
    public JCAContext getJCAContext() {
        return null;
    }
}
