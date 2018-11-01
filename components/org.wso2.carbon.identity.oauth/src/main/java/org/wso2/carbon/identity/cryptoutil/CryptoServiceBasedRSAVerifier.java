package org.wso2.carbon.identity.cryptoutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.jca.JCAContext;
import com.nimbusds.jose.util.Base64URL;
import org.wso2.carbon.crypto.api.CryptoContext;
import org.wso2.carbon.crypto.api.CryptoException;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.identity.cryptoutil.internal.CryptoUtilDataHolder;

import java.util.Set;

/**
 * Implementation of {@link JWSVerifier} based on Carbon Crypto Service.
 * Instances of this class provides JWT verification using Carbon Crypto Service.
 */
public class CryptoServiceBasedRSAVerifier implements JWSVerifier {

    private final CryptoContext cryptoContext;
    private final String jceProvider;
    private CryptoService cryptoService;

    /**
     * @param cryptoContext : Context related to data to be verified.
     * @param jceProvider   : JCE Provider used for verification.
     */
    public CryptoServiceBasedRSAVerifier(CryptoContext cryptoContext, String jceProvider) {

        this.jceProvider = jceProvider;
        this.cryptoContext = cryptoContext;
        if (CryptoUtilDataHolder.getCryptoService() != null) {
            cryptoService = CryptoUtilDataHolder.getCryptoService();
        }
    }

    /**
     * Verify a given signature with given data using Carbon Crypto Service.
     *
     * @param jwsHeader        : {@link JWSHeader}
     * @param dataToBeVerified : Data that needs to be verified.
     * @param signature        : Signature
     * @return
     * @throws JOSEException
     */
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

    /**
     * Returns the set of supported algorithms{@link JWSAlgorithm} by the CryptoServiceBasedRSAVerifier.
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
