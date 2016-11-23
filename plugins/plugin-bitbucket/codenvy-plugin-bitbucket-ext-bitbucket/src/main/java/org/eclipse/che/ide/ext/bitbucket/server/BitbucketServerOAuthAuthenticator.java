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
package org.eclipse.che.ide.ext.bitbucket.server;

import com.google.api.client.auth.oauth.OAuthAuthorizeTemporaryTokenUrl;
import com.google.api.client.auth.oauth.OAuthCredentialsResponse;
import com.google.api.client.auth.oauth.OAuthGetAccessToken;
import com.google.api.client.auth.oauth.OAuthGetTemporaryToken;
import com.google.api.client.auth.oauth.OAuthParameters;
import com.google.api.client.auth.oauth.OAuthRsaSigner;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Base64;
import com.google.inject.Singleton;

import org.eclipse.che.api.auth.shared.dto.OAuthToken;
import org.eclipse.che.security.oauth.OAuthAuthenticationException;
import org.eclipse.che.security.oauth.OAuthAuthenticator;
import org.eclipse.che.security.oauth.shared.User;

import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import static java.net.URLDecoder.decode;
import static org.eclipse.che.dto.server.DtoFactory.newDto;

/**
 * OAuth authentication for Bitbucket server account.
 *
 * @author Igor Vinokur
 */
@Singleton
public class BitbucketServerOAuthAuthenticator extends OAuthAuthenticator {

    private static final String USER_ID_PARAM_KEY        = "userId";
    private static final String STATE_PARAM_KEY          = "state";
    private static final String OAUTH_TOKEN_PARAM_KEY    = "oauth_token";
    private static final String OAUTH_VERIFIER_PARAM_KEY = "oauth_verifier";

    private static final String GET              = HttpMethod.GET;
    private static final String AUTHORIZATION    = "Authorization";
    private static final String ACCEPT           = HttpHeaders.ACCEPT;
    private static final String APPLICATION_JSON = MediaType.APPLICATION_JSON;

    private final String                                consumerKey;
    private final String                                privateKey;
    private final String                                authUri;
    private final String                                requestTokenUri;
    private final String                                requestAccessTokenUri;
    private final String                                redirectUri;
    private final ReentrantLock                         credentialsStoreLock;
    private final HttpTransport                         httpTransport;
    private final Map<String, String>                   sharedTokenSecrets;
    private final Map<String, OAuthCredentialsResponse> credentialsStore;

    //    @Inject
//    public BitbucketServerOAuthAuthenticator(@Named("oauth.bitbucket_server.clientid") String clientId,
//                                             @Named("oauth.bitbucket_server.consumerKey") String consumerKey,
//                                             @Named("oauth.bitbucket_server.privateKey") String privateKey,
//                                             @Named("oauth.bitbucket_server.authuri") String authUri,
//                                             @Named("oauth.bitbucket_server.requesttokenuri") String requestTokenUri,
//                                             @Named("oauth.bitbucket_server.requestaccesstokenuri") String requestAccessTokenUri,
//                                             @Named("oauth.bitbucket_server.verifyaccesstokenuri") String verifyAccessTokenUri,
//                                             @Named("oauth.bitbucket_server.redirecturis") String redirectUri) throws IOException {
    @Inject
    public BitbucketServerOAuthAuthenticator() throws IOException {

//        this.clientId = clientId;
//        this.consumerKey = consumerKey;
//        this.privateKey = privateKey;
//        this.authUri = authUri;
//        this.requestTokenUri = requestTokenUri;
//        this.requestAccessTokenUri = requestAccessTokenUri;
//        this.verifyAccessTokenUri = verifyAccessTokenUri;
//        this.redirectUri = redirectUri;
//        this.httpTransport = new NetHttpTransport();
//        this.sharedTokenSecrets = new HashMap<>();
//        this.credentialsStore = new HashMap<>();
//        this.credentialsStoreLock = new ReentrantLock();

        this.consumerKey = "consumer123456";
        this.privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALhmj0yajPtj4Dug\n" +
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
        this.authUri = "http://bitbucket.codenvy-stg.com:7990/plugins/servlet/oauth/authorize";
        this.requestTokenUri = "http://bitbucket.codenvy-stg.com:7990/plugins/servlet/oauth/request-token";
        this.requestAccessTokenUri = "http://bitbucket.codenvy-stg.com:7990/plugins/servlet/oauth/access-token";
        this.redirectUri = "http://aio.codenvy-dev.com/";
        this.httpTransport = new NetHttpTransport();
        this.sharedTokenSecrets = new HashMap<>();
        this.credentialsStore = new HashMap<>();
        this.credentialsStoreLock = new ReentrantLock();
    }

    /**
     * Create authentication URL.
     *
     * @param requestUrl
     *         URL of current HTTP request. This parameter required to be able determine URL for redirection after
     *         authentication. If URL contains query parameters they will be copy to 'state' parameter and returned to
     *         callback method.
     * @return URL for authentication.
     */
    public String getAuthenticateUrl(final URL requestUrl)
            throws OAuthAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException {

        // construct the callback url
        final GenericUrl callbackUrl = new GenericUrl(redirectUri);
        callbackUrl.put(STATE_PARAM_KEY, requestUrl.getQuery());

        final BitBucketOAuthGetTemporaryToken getTemporaryToken = new BitBucketOAuthGetTemporaryToken(requestTokenUri);
        getTemporaryToken.signer = getOAuthRsaSigner(privateKey);
        getTemporaryToken.consumerKey = consumerKey;
        getTemporaryToken.callback = callbackUrl.build();
        getTemporaryToken.transport = httpTransport;

        try {

            final OAuthCredentialsResponse credentialsResponse = getTemporaryToken.execute();

            final OAuthAuthorizeTemporaryTokenUrl authorizeTemporaryTokenUrl = new OAuthAuthorizeTemporaryTokenUrl(authUri);
            authorizeTemporaryTokenUrl.temporaryToken = credentialsResponse.token;

            sharedTokenSecrets.put(credentialsResponse.token, credentialsResponse.tokenSecret);

            return authorizeTemporaryTokenUrl.build();

        } catch (final IOException e) {
            throw new OAuthAuthenticationException(e.getMessage());
        }
    }

    /**
     * Process callback request.
     *
     * @param requestUrl
     *         request URI. URI should contain OAuth token and OAuth verifier.
     * @return id of authenticated user
     * @throws OAuthAuthenticationException
     *         if authentication failed or {@code requestUrl} does not contain required parameters.
     */
    public String callback(final URL requestUrl) throws OAuthAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException {
        try {
            final GenericUrl callbackUrl = new GenericUrl(requestUrl.toString());

            if (callbackUrl.getFirst(OAUTH_TOKEN_PARAM_KEY) == null) {
                throw new OAuthAuthenticationException("Missing oauth_token parameter");
            }

            if (callbackUrl.getFirst(OAUTH_VERIFIER_PARAM_KEY) == null) {
                throw new OAuthAuthenticationException("Missing oauth_verifier parameter");
            }

            final String oauthTemporaryToken = (String)callbackUrl.getFirst(OAUTH_TOKEN_PARAM_KEY);

            final BitBucketOAuthGetAccessToken getAccessToken = new BitBucketOAuthGetAccessToken(requestAccessTokenUri);
            getAccessToken.consumerKey = consumerKey;
            getAccessToken.temporaryToken = oauthTemporaryToken;
            getAccessToken.verifier = (String)callbackUrl.getFirst(OAUTH_VERIFIER_PARAM_KEY);
            getAccessToken.transport = httpTransport;
            getAccessToken.signer = getOAuthRsaSigner(privateKey);

            final OAuthCredentialsResponse credentials = getAccessToken.execute();
            final String state = (String)callbackUrl.getFirst(STATE_PARAM_KEY);

            String userId = getUserFromStateParameter(state);
            if (userId == null) {
                userId = getUser(newDto(OAuthToken.class).withToken(credentials.token)).getId();
            }

            credentialsStoreLock.lock();
            try {

                final OAuthCredentialsResponse currentCredentials = credentialsStore.get(userId);
                if (currentCredentials == null) {
                    credentialsStore.put(userId, credentials);

                } else {
                    currentCredentials.token = credentials.token;
                    currentCredentials.tokenSecret = credentials.tokenSecret;
                }

            } finally {
                credentialsStoreLock.unlock();
            }

            return userId;

        } catch (final IOException e) {
            throw new OAuthAuthenticationException(e.getMessage());
        }
    }

    /**
     * Compute the Authorization header to sign the OAuth 1 request.
     *
     * @param requestMethod
     *         the HTTP request method.
     * @param requestUrl
     *         the HTTP request url with encoded query parameters.
     * @param requestParameters
     *         the HTTP request parameters. HTTP request parameters must include raw values of application/x-www-form-urlencoded POST
     *         parameters.
     * @param token
     *         the token.
     * @return the authorization header value, or {@code null}.
     */
    private String computeAuthorizationHeader(final String requestMethod,
                                              final String requestUrl,
                                              final Map<String, String> requestParameters,
                                              final String token) throws InvalidKeySpecException, NoSuchAlgorithmException {

        final OAuthParameters oauthParameters = new OAuthParameters();
        oauthParameters.consumerKey = consumerKey;
        oauthParameters.signer = getOAuthRsaSigner(privateKey);
        oauthParameters.token = token;
        oauthParameters.version = "1.0";

        oauthParameters.computeNonce();
        oauthParameters.computeTimestamp();

        final GenericUrl genericRequestUrl = new GenericUrl(requestUrl);
        genericRequestUrl.putAll(requestParameters);

        try {

            oauthParameters.computeSignature(requestMethod, genericRequestUrl);

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }

        return oauthParameters.getAuthorizationHeader();
    }


    /**
     * Extract the user id from the state parameter.
     *
     * @param state
     *         the state parameter value.
     * @return the user id or {@code null} if not found.
     */
    private String getUserFromStateParameter(final String state) {
        if (state != null && !state.trim().isEmpty()) {
            final String decodedState;
            try {

                decodedState = decode(state, "UTF-8");

            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException(e);
            }

            final String[] params = decodedState.split("&");
            for (final String oneParam : params) {
                if (oneParam.startsWith(USER_ID_PARAM_KEY + "=")) {
                    return oneParam.substring(7, oneParam.length());
                }
            }
        }
        return null;
    }

    private OAuthRsaSigner getOAuthRsaSigner(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
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

    @Override
    public User getUser(OAuthToken accessToken) throws OAuthAuthenticationException {
//        final BitbucketUser user = getJson("https://api.bitbucket.org/2.0/user", token, tokenSecret, BitbucketUser.class);
//        final BitbucketEmail[] emails = getJson("https://api.bitbucket.org/1.0/emails", token, tokenSecret, BitbucketEmail[].class);
//
//        BitbucketEmail primaryEmail = null;
//        for (final BitbucketEmail oneEmail : emails) {
//            if (oneEmail.isPrimary()) {
//                primaryEmail = oneEmail;
//                break;
//            }
//        }
//
//        if (primaryEmail == null || primaryEmail.getEmail() == null || primaryEmail.getEmail().isEmpty()) {
//            throw new OAuthAuthenticationException("Sorry, we failed to find any primary emails associated with your Bitbucket account.");
//        }
//
//        user.setEmail(primaryEmail.getEmail());
//
//        try {
//
//            new InternetAddress(user.getEmail()).validate();
//
//        } catch (final AddressException e) {
//            throw new OAuthAuthenticationException(e);
//        }
//
//        return user;
        return null;
    }

    @Override
    public String getOAuthProvider() {
        return "bitbucket-server";
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
//MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4Zo9Mmoz7Y+A7oCbwIjKKbfKd
//        uQ8e0yRYZpf9vFjpsGggzr2uj3CYcSTYCSvRp3PUB0EQy3DIkK4gkMFBvnX+yKfJ
//        Mo5gp9oJY4hYRpN25qcxz2mzlSTPAYkFXYn9IcowfKYzymdOtCaGNEORbZ5ns3vd
//        4AnFH5/Y8TD63cCeQQIDAQAB