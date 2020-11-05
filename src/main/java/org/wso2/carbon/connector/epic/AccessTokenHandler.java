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
import org.wso2.carbon.connector.epic.security.KeyCreator;
import org.wso2.carbon.connector.epic.security.KeystoreKeyCreator;
import org.wso2.carbon.connector.epic.security.PlaintextKeyCreator;
import org.wso2.carbon.connector.epic.security.Token;
import org.wso2.carbon.connector.epic.security.TokenManager;

/**
 * This class will handle retrieval of access token
 */
public class AccessTokenHandler extends AbstractConnector {

    private static final Log LOG = LogFactory.getLog(AccessTokenHandler.class);

    public AccessTokenHandler() {
        //TODO clean log
        LOG.info("AccessTokenHandler New Instance");
    }

    @Override
    public void connect(MessageContext messageContext) throws ConnectException {
        String accessToken = (String) messageContext.getProperty(Constants.EPIC_ACCESS_TOKEN);
        String clientId = (String) messageContext.getProperty(Constants.EPIC_CLIENT_ID);
        String tokenEP = (String) messageContext.getProperty(Constants.EPIC_TOKEN_EP);

        String privateKey = (String) getParameter(messageContext, Constants.EPIC_PRIVATE_KEY);
        String keystore = (String) getParameter(messageContext, Constants.EPIC_KEYSTORE);
        String keyAlias = (String) getParameter(messageContext, Constants.EPIC_KEY_ALIAS);
        String keyPass = (String) getParameter(messageContext, Constants.EPIC_KEY_PASS);

        if (accessToken == null) {
            // Parameter check
            if (clientId == null || tokenEP == null ||
                    (privateKey == null && (keystore == null || keyAlias == null || keyPass == null))) {
                StringBuilder errMessageBuilder = new StringBuilder("Following parameters in init operation are missing : ");
                if (clientId == null) {
                    errMessageBuilder.append(" \"clientId\",");
                }
                if (tokenEP == null) {
                    errMessageBuilder.append(" \"tokenEndpoint\",");
                }

                if (keystore != null || keyAlias != null) {
                    if (keystore == null) {
                        errMessageBuilder.append(" \"keyStore\",");
                    }
                    if (keyAlias == null) {
                        errMessageBuilder.append(" \"privateKeyAlias\",");
                    }
                    if (keyPass == null) {
                        errMessageBuilder.append(" \"keyStorePass\",");
                    }
                } else if (privateKey == null) {
                    errMessageBuilder.append(" \"privateKey\",");
                }
                throw new EpicConnectorException(errMessageBuilder.toString());
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Retrieving access token from TokenManager");
            }

            Token token = TokenManager.getToken(clientId, tokenEP);
            if (token == null || !token.isActive()) {
                KeyCreator privateKeyCreator = null;
                //Get new access token
                if (privateKey != null) {
                    privateKeyCreator = new PlaintextKeyCreator(privateKey);
                } else {
                    privateKeyCreator = new KeystoreKeyCreator(keystore, keyPass.toCharArray(), keyAlias);
                }
                token = TokenManager.getNewToken(clientId, privateKeyCreator, tokenEP, messageContext);
            }
            messageContext.setProperty(Constants.EPIC_ACCESS_TOKEN, token.getAccessToken());
        }
    }
}
