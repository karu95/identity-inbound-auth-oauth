package org.wso2.carbon.identity.oauth2.util.cryptoutil;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;

import java.util.LinkedHashSet;
import java.util.Set;

public class CryptoServiceBasedRSASSA {

    private static final Set<JWSAlgorithm> algorithms = new LinkedHashSet<JWSAlgorithm>() {{
        add(JWSAlgorithm.RS256);
        add(JWSAlgorithm.RS384);
        add(JWSAlgorithm.RS512);
        add(JWSAlgorithm.PS256);
        add(JWSAlgorithm.PS384);
        add(JWSAlgorithm.PS512);
    }};

    protected static String getSignVerifyAlgorithm(JWSAlgorithm alg) throws JOSEException {

        if (alg.equals(JWSAlgorithm.RS256)) {
            return "SHA256withRSA";
        } else if (alg.equals(JWSAlgorithm.RS384)) {
            return "SHA384withRSA";
        } else if (alg.equals(JWSAlgorithm.RS512)) {
            return "SHA512withRSA";
        } else if (alg.equals(JWSAlgorithm.PS256)) {
            return "SHA256withRSAandMGF1";
        } else if (alg.equals(JWSAlgorithm.PS384)) {
            return "SHA384withRSAandMGF1";
        } else if (alg.equals(JWSAlgorithm.PS512)) {
            return "SHA512withRSAandMGF1";
        } else {
            String errorMessage = String.format("Requested sign/verify '%s' algorithm is not supported.",
                    alg.getName());
            throw new JOSEException(errorMessage);
        }
    }

    public static Set<JWSAlgorithm> getSupportedAlgorithms() {
        return algorithms;
    }

    private CryptoServiceBasedRSASSA() {
    }
}
