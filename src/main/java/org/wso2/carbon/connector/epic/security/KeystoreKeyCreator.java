/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.connector.epic.security;

import org.apache.axiom.om.OMText;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.wso2.carbon.connector.epic.EpicConnectorException;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import javax.activation.DataHandler;

public class KeystoreKeyCreator implements KeyCreator {

    private static final Log LOG = LogFactory.getLog(KeystoreKeyCreator.class);
    private static final String REG_GOV_PREFIX = "gov:";
    private static final String REG_CONF_PREFIX = "config:";
    private static final String REG_DEFAULT_PATH = "gov:/repository/security/key-stores/";
    private static final String FILE_PATH_PREFIX = "file:";

    private String keystore;
    private char[] storePass;
    private String alias;

    public KeystoreKeyCreator(String keystore, char[] storePass, String alias) {
        this.keystore = keystore;
        this.storePass = storePass;
        this.alias = alias;
    }

    @Override
    public PrivateKey getKey(MessageContext context) throws EpicConnectorException {
        KeyStore keyStore;
        if (LOG.isDebugEnabled()) {
            LOG.debug("Loading private ker from :" + keystore);
        }
        if (keystore.startsWith(FILE_PATH_PREFIX)) {
            keyStore = loadKeyStoreFromFile(keystore, storePass);
        } else if (keystore.startsWith(REG_CONF_PREFIX) || keystore.startsWith(REG_GOV_PREFIX)) {
            keyStore = loadKeyStoreFromRegistry(keystore, storePass, context);
        } else {
            keyStore = loadKeyStoreFromRegistry(REG_DEFAULT_PATH + keystore, storePass, context);
        }

        try {
            Key key = keyStore.getKey(alias, storePass);
            if (key instanceof PrivateKey) {
                cleanSensitiveData();
                return (PrivateKey) key;
            } else {
                throw new EpicConnectorException("The key alias:" + alias + " is not pointing a private key");
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            throw new EpicConnectorException(e, "Error occurred while retrieving private key : " + alias +
                    " from the KeyStore: " + keystore);
        }
    }


    private static KeyStore loadKeyStoreFromRegistry(String keyStorePath, char[] storePass, MessageContext context)
            throws EpicConnectorException {
        try {
            Object obj = context.getEntry(keyStorePath);
            if (obj instanceof OMText) {
                KeyStore keyStore = KeyStore.getInstance("JKS");
                OMText objText = (OMText) obj;
                if (objText.isBinary() && objText.getDataHandler() instanceof DataHandler) {
                    DataHandler dataHandler = (DataHandler) objText.getDataHandler();
                    keyStore.load(dataHandler.getInputStream(), storePass);
                    return keyStore;
                } else {
                    throw new EpicConnectorException("Unable to read keystore from the registry. Ensure the Media " +
                            "Type of the registry resource ("+ keyStorePath + ") is set to " +
                            "\"application/x-java-keystore\"");
                }
            } else {
                throw new EpicConnectorException("Unexpected resource entry: " + keyStorePath);
            }

        } catch (IOException | NoSuchAlgorithmException | CertificateException | KeyStoreException e) {
            throw new EpicConnectorException(e, "Error occurred while loading Keystore from registry");
        }
    }

    private KeyStore loadKeyStoreFromFile(String keyStoreFilePath, char[] storePass) throws EpicConnectorException {
        try {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream(keyStoreFilePath), storePass);
            return keyStore;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new EpicConnectorException(e, "Error occurred while loading the keystore");
        }

    }

    /**
     * Function to clear private key data in memory
     */
    private void cleanSensitiveData() {
        Arrays.fill(storePass, '0');
    }
}
