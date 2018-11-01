package org.wso2.carbon.identity.cryptoutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * This class is used to keep supported algorithms {@link JWSAlgorithm} by Crypto Service Based sign and verification.
 * Also this class is used for resolving {@link JWSAlgorithm} to Standard JCE naming.
 */
class CryptoServiceBasedRSASSA {

    private static final Set<JWSAlgorithm> algorithms = new LinkedHashSet<JWSAlgorithm>() {{
        add(JWSAlgorithm.RS256);
        add(JWSAlgorithm.RS384);
        add(JWSAlgorithm.RS512);
        add(JWSAlgorithm.PS256);
        add(JWSAlgorithm.PS384);
        add(JWSAlgorithm.PS512);
    }};

    private CryptoServiceBasedRSASSA() {
    }

    /**
     * Resolves standard JCE name for given {@link JWSAlgorithm}
     *
     * @param jwsAlgorithm ; {@link JWSAlgorithm} that needs to be resolved.
     * @return Standard JCE name for the given JWS algorithm.
     * @throws JOSEException
     */
    static String getSignVerifyAlgorithm(JWSAlgorithm jwsAlgorithm) throws JOSEException {

        if (jwsAlgorithm.equals(JWSAlgorithm.RS256)) {
            return "SHA256withRSA";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.RS384)) {
            return "SHA384withRSA";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.RS512)) {
            return "SHA512withRSA";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.PS256)) {
            return "SHA256withRSAandMGF1";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.PS384)) {
            return "SHA384withRSAandMGF1";
        } else if (jwsAlgorithm.equals(JWSAlgorithm.PS512)) {
            return "SHA512withRSAandMGF1";
        } else {
            String errorMessage = String.format("Requested sign/verify '%s' algorithm is not supported.",
                    jwsAlgorithm.getName());
            throw new JOSEException(errorMessage);
        }
    }

    /**
     * Returns set of supported {@link JWSAlgorithm}
     *
     * @return
     */
    static Set<JWSAlgorithm> getSupportedAlgorithms() {
        return algorithms;
    }
}
