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
