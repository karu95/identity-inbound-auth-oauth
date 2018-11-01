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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.base.api.ServerConfigurationService;
import org.wso2.carbon.crypto.api.CryptoService;
import org.wso2.carbon.crypto.api.KeyResolver;
import org.wso2.carbon.identity.cryptoutil.OAuthServiceProviderKeyResolver;

@Component(
        name = "identity.cryptoutil.component",
        immediate = true
)
public class CryptoUtilComponent {

    private static Log log = LogFactory.getLog(CryptoUtilComponent.class);

    private ServiceRegistration<KeyResolver> oauthKeyResolverServiceRegistration;

    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            BundleContext bundleContext = componentContext.getBundleContext();
            KeyResolver oauthKeyResolver = new OAuthServiceProviderKeyResolver(CryptoUtilDataHolder.getServerConfigurationService());
            oauthKeyResolverServiceRegistration = bundleContext.registerService(KeyResolver.class, oauthKeyResolver,
                    null);
            if (log.isInfoEnabled()) {
                String message = String.format("'%s' activated successfully.", OAuthServiceProviderKeyResolver.class);
                log.info(message);
            }
        } catch (Throwable e) {
            String errorMessage = String.format("Error occurred while activating '%s'", CryptoUtilComponent.class);
            if (log.isInfoEnabled()) {
                log.info(errorMessage, e);
            }
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext componentContext) {

        oauthKeyResolverServiceRegistration.unregister();
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        CryptoUtilDataHolder.unsetServerConfigurationService();
    }

    @Reference(
            name = "serverConfigurationService",
            service = ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerConfigurationService"
    )
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        CryptoUtilDataHolder.setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetCryptoService(CryptoService cryptoService) {

        CryptoUtilDataHolder.unsetCryptoService();
    }

    @Reference(
            name = "cryptoService",
            service = CryptoService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetCryptoService"
    )
    protected void setCryptoService(CryptoService cryptoService) {

        CryptoUtilDataHolder.setCryptoService(cryptoService);
    }
}
