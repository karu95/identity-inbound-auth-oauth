package org.wso2.carbon.identity.oauth2.util.cryptoutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.Set;

/**
 * Implementation of {@link JWSSigner} based on Carbon Crypto Service.
 */
public class CryptoServiceBasedRSASigner implements JWSSigner {

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    /**
     *
     *
     * @param cryptoContext
     * @param jceProvider
     */
    public CryptoServiceBasedRSASigner(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (OAuth2ServiceComponentHolder.getCryptoService() != null) {
            cryptoService = OAuth2ServiceComponentHolder.getCryptoService();
        }
    }

    /**
     *
     *
     * @param jwsHeader
     * @param dataToBeSigned
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
