package org.wso2.carbon.identity.oauth2.util.cryptoutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.identity.oauth2.internal.OAuth2ServiceComponentHolder;

import java.util.Set;

public class CryptoServiceBasedRSAVerifier implements JWSVerifier {

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    public CryptoServiceBasedRSAVerifier(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (OAuth2ServiceComponentHolder.getCryptoService() != null) {
            cryptoService = OAuth2ServiceComponentHolder.getCryptoService();
        }
    }

    @Override
    public boolean verify(JWSHeader jwsHeader, byte[] dataToBeVerified, Base64URL signature) throws JOSEException {
        String algorithm = CryptoServiceBasedRSASSA.getSignVerifyAlgorithm(jwsHeader.getAlgorithm());
        try {
            return cryptoService.verifySignature(dataToBeVerified, signature.decode(), algorithm, jceProvider, cryptoContext);
        } catch (CryptoException e) {
            String errorMessage = String.format("Error occurred while verifying JWT signature using '%s' algorithm",
                    algorithm);
            throw new JOSEException(errorMessage, e);
        }
    }

    @Override
    public Set<JWSAlgorithm> supportedJWSAlgorithms() {
        return CryptoServiceBasedRSASSA.getSupportedAlgorithms();
    }

    @Override
    public JCAContext getJCAContext() {
        return null;
    }
}
