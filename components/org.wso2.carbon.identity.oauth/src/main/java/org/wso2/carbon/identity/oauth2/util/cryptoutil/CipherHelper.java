package org.wso2.carbon.identity.oauth2.util.cryptoutil;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;

import java.util.LinkedHashSet;
import java.util.Set;

class CipherHelper {

    private static final Set<JWEAlgorithm> algorithms = new LinkedHashSet<JWEAlgorithm>() {{
        add(JWEAlgorithm.RSA1_5);
        add(JWEAlgorithm.RSA_OAEP);
        add(JWEAlgorithm.RSA_OAEP_256);
    }};

    private static final Set<EncryptionMethod> encryptionMethods = new LinkedHashSet<EncryptionMethod>() {{
        add(EncryptionMethod.A128GCM);
        add(EncryptionMethod.A192GCM);
        add(EncryptionMethod.A256GCM);
    }};

    static Set<JWEAlgorithm> getSupportedAlgorithms() {

        return algorithms;
    }

    static Set<EncryptionMethod> getSupportedEncryptionMethods() {

        return encryptionMethods;
    }

    static String resolveAsymmetricAlgorithm(JWEAlgorithm encryptionAlgorithm) throws JOSEException {

        if (encryptionAlgorithm.equals(JWEAlgorithm.RSA1_5)) {
            return "RSA/ECB/PKCS1Padding";
        } else if (encryptionAlgorithm.equals(JWEAlgorithm.RSA_OAEP)) {
            return "RSA/ECB/OAEPwithSHA1andMGF1Padding";
        } else if (encryptionAlgorithm.equals(JWEAlgorithm.RSA_OAEP_256)) {
            return "RSA/ECB/OAEPwithSHA256andMGF1Padding";
        } else {
            String errorMessage = String.format("Requested asymmetric algorithm '%s' is not supported.",
                    encryptionAlgorithm.getName());
            throw new JOSEException(errorMessage);
        }
    }

    static String resolveSymmetricAlgorithm(EncryptionMethod encryptionMethod) throws JOSEException {

        if (encryptionMethod.equals(EncryptionMethod.A128GCM)) {
            return "AES_128/GCM/NoPadding";
        } else if (encryptionMethod.equals(EncryptionMethod.A192GCM)) {
            return "AES_192/GCM/NoPadding";
        } else if (encryptionMethod.equals(EncryptionMethod.A256GCM)) {
            return "AES_256/GCM/NoPadding";
        } else {
            String errorMessage = String.format("Requested symmetric algorithm '%s' is not supported by " +
                            "Crypto Service based RSA provider.", encryptionMethod.getName());
            throw new JOSEException(errorMessage);
        }
    }
}
