/*
 *  Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.connector.epic;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.wso2.carbon.connector.core.AbstractConnector;
import org.wso2.carbon.connector.core.ConnectException;
import org.wso2.carbon.connector.epic.security.TokenManager;

/**
 * This class will validate response status code and clean relevant token from the map
 */
public class ResponseValidateHandler extends AbstractConnector {

    private static Log LOG = LogFactory.getLog(ResponseValidateHandler.class);

    public ResponseValidateHandler() {
    }

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {

        if (messageContext instanceof Axis2MessageContext) {
            org.apache.axis2.context.MessageContext axis2mc = ((Axis2MessageContext) messageContext).getAxis2MessageContext();
            int httpStatus = (Integer) axis2mc.getProperty("HTTP_SC");
            String clientId = (String) messageContext.getProperty(Constants.EPIC_CLIENT_ID);
            String tokenEP = (String) messageContext.getProperty(Constants.EPIC_TOKEN_EP);
            if ((clientId != null || tokenEP!= null) && httpStatus >= 400) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Unauthorized response received, hence removing access token from the token map");
                }
                //Remove access token from the token map
                TokenManager.removeToken(clientId, tokenEP);
            }
        }

    }





}
