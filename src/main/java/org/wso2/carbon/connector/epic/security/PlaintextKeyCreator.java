package org.wso2.carbon.connector.epic.security;

import org.apache.commons.codec.binary.Base64;
import org.apache.synapse.MessageContext;
import org.wso2.carbon.connector.epic.EpicConnectorException;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

public class PlaintextKeyCreator implements KeyCreator{

    private final byte[] keyStr;

    public PlaintextKeyCreator(String keyString) {
        this.keyStr = keyString.getBytes();
    }

    @Override
    public PrivateKey getKey(MessageContext context) throws EpicConnectorException {
        try {
            byte[] encoded = Base64.decodeBase64(keyStr);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            cleanSensitiveData();
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            String message = "Error occurred while retrieving private key object";
            throw new EpicConnectorException(e, message);
        }
    }

    /**
     * Function to clear private key data in memory
     */
    private void cleanSensitiveData() {
        Arrays.fill(keyStr, (byte) 0);
    }
}
