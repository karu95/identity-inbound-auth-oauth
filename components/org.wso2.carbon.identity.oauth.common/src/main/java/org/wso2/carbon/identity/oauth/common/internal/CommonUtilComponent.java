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

package org.wso2.carbon.identity.oauth.common.internal;

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
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.oauth.common.cryptooperators.ServiceProviderKeyResolver;

@Component(
        name = "identity.oauth.common.component",
        immediate = true
)
public class CommonUtilComponent {

    private static Log log = LogFactory.getLog(CommonUtilComponent.class);

    private ServiceRegistration<KeyResolver> serviceProviderKeyResolverServiceRegistration;

    @Activate
    protected void activate(ComponentContext componentContext) {

        try {
            BundleContext bundleContext = componentContext.getBundleContext();
            KeyResolver oauthKeyResolver = new
                    ServiceProviderKeyResolver(CommonUtilDataHolder.getServerConfigurationService());
            serviceProviderKeyResolverServiceRegistration = bundleContext.registerService(KeyResolver.class,
                    oauthKeyResolver, null);
            if (log.isInfoEnabled()) {
                String message = String.format("Service provider key resolver activated successfully.",
                        ServiceProviderKeyResolver.class);
                log.info(message);
            }
        } catch (Throwable e) {
            String errorMessage = String.format("Error occurred while activating '%s'", CommonUtilComponent.class);
            log.error(errorMessage, e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext componentContext) {

        serviceProviderKeyResolverServiceRegistration.unregister();
    }

    @Reference(
            name = "serverConfigurationService",
            service = ServerConfigurationService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetServerConfigurationService"
    )
    protected void setServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        CommonUtilDataHolder.setServerConfigurationService(serverConfigurationService);
    }

    protected void unsetServerConfigurationService(ServerConfigurationService serverConfigurationService) {

        CommonUtilDataHolder.unsetServerConfigurationService();
    }

    @Reference(
            name = "cryptoService",
            service = CryptoService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetCryptoService"
    )
    protected void setCryptoService(CryptoService cryptoService) {

        CommonUtilDataHolder.setCryptoService(cryptoService);
    }

    protected void unsetCryptoService(CryptoService cryptoService) {

        CommonUtilDataHolder.unsetCryptoService();
    }

    @Reference(
            name = "application.mgt.service",
            service = ApplicationManagementService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetApplicationMgtService"
    )
    protected void setApplicationMgtService(ApplicationManagementService applicationMgtService) {

        CommonUtilDataHolder.setApplicationMgtService(applicationMgtService);
    }

    protected void unsetApplicationMgtService(ApplicationManagementService applicationMgtService) {

        CommonUtilDataHolder.unsetApplicationManagementService(applicationMgtService);
    }
}
