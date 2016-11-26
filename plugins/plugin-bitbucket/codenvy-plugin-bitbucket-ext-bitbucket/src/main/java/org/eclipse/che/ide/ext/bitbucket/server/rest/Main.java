/*
 *  [2012] - [2016] Codenvy, S.A.
 *  All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Codenvy S.A. and its suppliers,
 * if any.  The intellectual and technical concepts contained
 * herein are proprietary to Codenvy S.A.
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Codenvy S.A..
 */
package org.eclipse.che.ide.ext.bitbucket.server.rest;


import com.google.api.client.auth.oauth.OAuthAuthorizeTemporaryTokenUrl;
import com.google.api.client.auth.oauth.OAuthCallbackUrl;
import com.google.api.client.auth.oauth.OAuthCredentialsResponse;
import com.google.api.client.auth.oauth.OAuthGetAccessToken;
import com.google.api.client.auth.oauth.OAuthGetTemporaryToken;
import com.google.api.client.auth.oauth.OAuthHmacSigner;
import com.google.api.client.auth.oauth.OAuthParameters;
import com.google.api.client.auth.oauth.OAuthRsaSigner;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Base64;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class Main {

    private static String privateKey         = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALhmj0yajPtj4Dug\n" +
                                               "JvAiMopt8p25Dx7TJFhml/28WOmwaCDOva6PcJhxJNgJK9Gnc9QHQRDLcMiQriCQ\n" +
                                               "wUG+df7Ip8kyjmCn2gljiFhGk3bmpzHPabOVJM8BiQVdif0hyjB8pjPKZ060JoY0\n" +
                                               "Q5Ftnmeze93gCcUfn9jxMPrdwJ5BAgMBAAECgYAzVfIM7HXVQp/ZWaOddJfHbAaA\n" +
                                               "HFX2SeezaJRlwjqqjD7g601pPGunNNCCCEOXsVuQqphVmZ2DaKvhSwtSRzjHxRRN\n" +
                                               "yAzOR36Z6W/ALbqJq6Z8R754E0XTKdUKg3GmJ2G09czlrFauv8tc1Jw/UpKgP6JA\n" +
                                               "u51+KFhwt5WqsizYcQJBAO2v0P6kxG1g1RgiZxomLNzbvouCYRDmXwsk0NymvbCy\n" +
                                               "71GeWg0LSAEwAfu0KqxbXTWUmblabhJ8FIL9LpeeaZUCQQDGm7dRPl5N6Izt6aw7\n" +
                                               "OEYJZlBk9vg+Qek2E4x1YTnXxf6uUq/BQVLP1nJC5myQ/sDhWYun+soKJIYsayIa\n" +
                                               "8679AkEA0ftjXbPevOqxF5M9FsLnG28e1U0nx7BeAxBRXL4KExLhjm+hCqkOwc3R\n" +
                                               "0raGhKJqpC1V6YRUfgwUauyVvuj6SQJAQ3MEudm1iz3sBqxyKpZ86ppNuUxKmFIo\n" +
                                               "Eo5nCEIhs87xJGC+gaJermkE2wWIX2G1PZL8o+q/DNzEmHc12PNjPQJBANyJJW3E\n" +
                                               "NmPbPBo56PD6mFNuZiR2nUymH/P9vu9gm58qofshqOwe/wGJB0Q9sqp86oW3eRFd\n" +
                                               "0191X1dDSH/gLr8=";
    private static String oauth_consumer_key = "consumer123456";
    private static String requestUrl         = "http://bitbucket.codenvy-stg.com:7990/plugins/servlet/oauth/request-token";
    private static String accessUrl          = "http://bitbucket.codenvy-stg.com:7990/plugins/servlet/oauth/access-token";
    private static String authUrl            = "http://bitbucket.codenvy-stg.com:7990/plugins/servlet/oauth/authorize";


    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        BitBucketOAuthGetTemporaryToken getTemporaryToken = new BitBucketOAuthGetTemporaryToken(requestUrl);
        getTemporaryToken.signer = getOAuthRsaSigner(privateKey);
        getTemporaryToken.consumerKey = oauth_consumer_key;
        getTemporaryToken.callback = "http://localhost";
        getTemporaryToken.transport = new NetHttpTransport();


        OAuthCredentialsResponse temporaryTokenResponse = getTemporaryToken.execute();

        OAuthAuthorizeTemporaryTokenUrl authorizeTemporaryTokenUrl = new OAuthAuthorizeTemporaryTokenUrl(authUrl);
        authorizeTemporaryTokenUrl.temporaryToken = temporaryTokenResponse.token;
        authorizeTemporaryTokenUrl.build();


        BitBucketOAuthGetAccessToken oAuthGetAccessToken = new BitBucketOAuthGetAccessToken(accessUrl);
        oAuthGetAccessToken.signer = getOAuthRsaSigner(privateKey);
        oAuthGetAccessToken.consumerKey = oauth_consumer_key;
        oAuthGetAccessToken.temporaryToken = temporaryTokenResponse.token;
        oAuthGetAccessToken.transport = new NetHttpTransport();
        oAuthGetAccessToken.verifier = "ogfbTa";

        OAuthCredentialsResponse accessTokenResponse = oAuthGetAccessToken.execute();

        OAuthParameters oauthParameters = new OAuthParameters();
        oauthParameters.consumerKey = oauth_consumer_key;
        oauthParameters.signer = getOAuthRsaSigner(privateKey);
        oauthParameters.token = accessTokenResponse.token;
        oauthParameters.version = "1.0";

        oauthParameters.computeNonce();
        oauthParameters.computeTimestamp();

        final GenericUrl genericRequestUrl =
                new GenericUrl("http://bitbucket.codenvy-stg.com:7990/rest/api/latest/projects/~IVINOKUR/repos/test/pull-requests");

        try {

            oauthParameters.computeSignature("GET", genericRequestUrl);

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        oauthParameters.getAuthorizationHeader();
    }

    private static OAuthRsaSigner getOAuthRsaSigner(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        OAuthRsaSigner oAuthRsaSigner = new OAuthRsaSigner();
        oAuthRsaSigner.privateKey = getPrivateKey(privateKey);
        return oAuthRsaSigner;
    }

    private static PrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private static class BitBucketOAuthGetTemporaryToken extends OAuthGetTemporaryToken {
        BitBucketOAuthGetTemporaryToken(String authorizationServerUrl) {
            super(authorizationServerUrl);
            super.usePost = true;
        }
    }

    private static class BitBucketOAuthGetAccessToken extends OAuthGetAccessToken {
        BitBucketOAuthGetAccessToken(String authorizationServerUrl) {
            super(authorizationServerUrl);
            super.usePost = true;
        }
    }
}
