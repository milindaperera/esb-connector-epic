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
package org.wso2.carbon.connector.epic.security;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.wso2.carbon.connector.epic.EpicConnectorException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This will hold and manage tokens
 */
public class TokenManager {

    private static final Log LOG = LogFactory.getLog(TokenManager.class);

    private static final JsonParser parser = new JsonParser();
    private static final Map<String, Token> tokenMap = new ConcurrentHashMap<>(4);

    /**
     * Function to get access to ken for given client ID and token EP
     * @param clientId
     * @param clientPrivateKey
     * @param tokenEP
     * @return
     * @throws EpicConnectorException
     */
    public static Token getAccessToken(String clientId, String clientPrivateKey, String tokenEP) throws EpicConnectorException {
        String tokenKey = clientId + "@" + tokenEP;
        Token token = tokenMap.get(tokenKey);
        if (token != null && token.isActive()) {
            return token;
        }
        return getNewToken(tokenKey, clientId, clientPrivateKey, tokenEP);
    }

    public static void removeToken(String clientId, String tokenEP) {
        String tokenKey = clientId + "@" + tokenEP;
        tokenMap.remove(tokenKey);
    }

    /**
     * Function to get new token
     *
     * @param clientId
     * @param clientPrivateKey
     * @param tokenEP
     * @return
     * @throws EpicConnectorException
     */
    private static synchronized Token getNewToken (String tokenKey, String clientId, String clientPrivateKey,
                                                   String tokenEP) throws EpicConnectorException {
        Token token = tokenMap.get(tokenKey);
        if (token == null || !token.isActive()) {
            String jwt = generateJWT(clientId, clientPrivateKey, tokenEP);
            token = requestAccessToken(tokenEP, jwt);
            tokenMap.put(tokenKey, token);
        }
        return token;
    }

    /**
     * Function to generate JWT
     *
     * @param clientId
     * @param clientPrivateKey
     * @param tokenEP
     * @return
     * @throws EpicConnectorException
     */
    private static String generateJWT(String clientId, String clientPrivateKey, String tokenEP) throws EpicConnectorException {
        try {
            RSAPrivateKey rsaPrivateKey = getPrivateKey(clientPrivateKey);
            JWSSigner signer = new RSASSASigner(rsaPrivateKey);
            long curTimeInMillis = System.currentTimeMillis();

            JWTClaimsSet.Builder claimsSetBuilder = new JWTClaimsSet.Builder();
            claimsSetBuilder.issuer(clientId);
            claimsSetBuilder.subject(clientId);
            claimsSetBuilder.audience(tokenEP);
            claimsSetBuilder.jwtID(UUID.randomUUID().toString());
            claimsSetBuilder.issueTime((new Date(curTimeInMillis)));
            claimsSetBuilder.notBeforeTime((new Date(curTimeInMillis)));
            claimsSetBuilder.expirationTime(new Date(curTimeInMillis + 300000)); //Maximum expiration time is 5 min
            JWTClaimsSet claimsSet = claimsSetBuilder.build();

            JWSAlgorithm signatureAlgorithm = new JWSAlgorithm(JWSAlgorithm.RS384.getName());
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(signatureAlgorithm);
            headerBuilder.type(JOSEObjectType.JWT);
            JWSHeader jwsHeader = headerBuilder.build();

            SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();

        } catch (JOSEException e) {
            String message = "Error occurred while signing the JWT";
            throw new EpicConnectorException(e, message);
        }
    }

    /**
     * Function to get private Key from key string
     *
     * @param sourcePrivateKey
     * @return
     * @throws EpicConnectorException
     */
    private static RSAPrivateKey getPrivateKey(String sourcePrivateKey) throws EpicConnectorException {
        String privateKeyPEM = sourcePrivateKey
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replaceAll(System.lineSeparator(), "")
                .replace("-----END RSA PRIVATE KEY-----", "");
        try {
            byte[] encoded = Base64.decodeBase64(privateKeyPEM.getBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            String message = "Error occurred while retrieving private key object";
            throw new EpicConnectorException(e, message);
        }
    }

    /**
     * Function to retrieve access token from token endpoint
     *
     * @param tokenEP
     * @param jwt
     * @return
     * @throws EpicConnectorException
     */
    private static Token requestAccessToken(String tokenEP, String jwt) throws EpicConnectorException {
        long curTimeInMillis = System.currentTimeMillis();
        HttpPost postRequest = new HttpPost(tokenEP);
        ArrayList<NameValuePair> parameters = new ArrayList<>();
        parameters.add(new BasicNameValuePair("grant_type", "client_credentials"));
        parameters.add(new BasicNameValuePair("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"));
        parameters.add(new BasicNameValuePair("client_assertion", jwt));

        try {
            postRequest.setEntity(new UrlEncodedFormEntity(parameters));
        } catch (UnsupportedEncodingException e) {
            throw new EpicConnectorException(e, "Error occurred while preparing access token request payload");
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault();
             CloseableHttpResponse response = httpClient.execute(postRequest)) {
            HttpEntity responseEntity = response.getEntity();
            if (responseEntity == null) {
                throw new EpicConnectorException("Failed to retrieve access token : No entity received");
            }
            int responseStatus = response.getStatusLine().getStatusCode();
            String respMessage = EntityUtils.toString(responseEntity);
            if (responseStatus == HttpURLConnection.HTTP_OK) {
                JsonElement jsonElement = parser.parse(respMessage);
                JsonObject jsonObject = jsonElement.getAsJsonObject();
                String accessToken = jsonObject.get("access_token").getAsString();
                long expireIn = jsonObject.get("expires_in").getAsLong();

                Token token = new Token(accessToken, curTimeInMillis, expireIn * 1000);
                if (LOG.isDebugEnabled()) {
                    LOG.debug(token);
                }
                return token;
            } else {
                String message = "Error occurred while retrieving access token. Response: " +
                                                                    "[Status : " + responseStatus + " " +
                                                                    "Message: " + respMessage + "]";
                throw new EpicConnectorException(message);
            }
        } catch (IOException e) {
            throw new EpicConnectorException(e, "Error occurred while retrieving access token");
        }
    }
}
