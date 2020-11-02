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
import org.wso2.carbon.connector.core.AbstractConnector;
import org.wso2.carbon.connector.core.ConnectException;
import org.wso2.carbon.connector.epic.security.Token;
import org.wso2.carbon.connector.epic.security.TokenManager;

/**
 * This class will handle retrieval of access token
 */
public class AccessTokenHandler extends AbstractConnector {

    private static final Log LOG = LogFactory.getLog(AccessTokenHandler.class);

    public AccessTokenHandler() {

    }

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        String clientId = (String) messageContext.getProperty(Constants.EPIC_CLIENT_ID);
        String privateKey = (String) messageContext.getProperty(Constants.EPIC_PRIVATE_KEY);
        String tokenEP = (String) messageContext.getProperty(Constants.EPIC_TOKEN_EP);

        if (clientId == null || privateKey == null || tokenEP == null) {
            String message = "\"clientId\", \"privateKey\", \"tokenEndpoint\" is a mandatory parameters when \"accessToken\" is " +
                    "not provided";
            throw new EpicConnectorException(message);
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("Retrieving access token from TokenManager");
        }
        Token token = TokenManager.getAccessToken(clientId, privateKey, tokenEP);
        messageContext.setProperty("uri.var.accessToken", token.getAccessToken());

    }





}
