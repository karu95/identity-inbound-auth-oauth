package org.wso2.carbon.identity.cryptoutil.internal;


import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoService;

/**
 * This holds required data for CryptoUtil Component.
 */
public class CryptoUtilDataHolder {

    private static ServerConfigurationService serverConfigurationService;
    private static CryptoService cryptoService;

    private CryptoUtilDataHolder() {
    }

    /**
     * Getter of the {@link ServerConfigurationService}
     *
     * @return
     */
    public static ServerConfigurationService getServerConfigurationService() {

        return serverConfigurationService;
    }

    static void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        CryptoUtilDataHolder.serverConfigurationService = serverConfigurationService;
    }

    /**
     * Getter of the {@link CryptoService}
     *
     * @return
     */
    public static CryptoService getCryptoService() {

        return cryptoService;
    }

    static void setCryptoService(CryptoService cryptoService) {

        CryptoUtilDataHolder.cryptoService = cryptoService;
    }

    static void unsetCryptoService() {

        CryptoUtilDataHolder.cryptoService = null;
    }

    static void unsetServerConfigurationService() {

        CryptoUtilDataHolder.serverConfigurationService = null;
    }

}
