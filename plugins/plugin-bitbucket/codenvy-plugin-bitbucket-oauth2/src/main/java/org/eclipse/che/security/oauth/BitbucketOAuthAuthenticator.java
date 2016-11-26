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
package org.eclipse.che.security.oauth;

import com.google.api.client.auth.oauth.OAuthAuthorizeTemporaryTokenUrl;
import com.google.api.client.auth.oauth.OAuthCredentialsResponse;
import com.google.api.client.auth.oauth.OAuthGetAccessToken;
import com.google.api.client.auth.oauth.OAuthGetTemporaryToken;
import com.google.api.client.auth.oauth.OAuthHmacSigner;
import com.google.api.client.auth.oauth.OAuthParameters;
import com.google.api.client.auth.oauth.OAuthRsaSigner;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Base64;
import com.google.api.client.util.store.MemoryDataStoreFactory;
import com.google.inject.Singleton;

import org.eclipse.che.api.auth.shared.dto.OAuthToken;
import org.eclipse.che.commons.annotation.Nullable;
import org.eclipse.che.commons.json.JsonHelper;
import org.eclipse.che.commons.json.JsonParseException;
import org.eclipse.che.commons.lang.IoUtil;
import org.eclipse.che.security.oauth.shared.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Named;
import javax.validation.constraints.NotNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import static com.google.common.base.Strings.isNullOrEmpty;
import static java.net.URLDecoder.decode;
import static java.util.Collections.emptyMap;
import static javax.ws.rs.HttpMethod.GET;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static org.eclipse.che.dto.server.DtoFactory.newDto;

/**
 * OAuth authentication for Bitbucket account.
 *
 * @author Michail Kuznyetsov
 */
@Singleton
public class BitbucketOAuthAuthenticator extends OAuthAuthenticator {

    private static final String STATE_PARAM_KEY          = "state";
    private static final String OAUTH_TOKEN_PARAM_KEY    = "oauth_token";
    private static final String OAUTH_VERIFIER_PARAM_KEY = "oauth_verifier";

    private static final Logger LOG = LoggerFactory.getLogger(BitbucketOAuthAuthenticator.class);

    private final String                                userUri;
    private final String                                clientId;
    private final String                                clientSecret;
    private final String                                authTokenUri;
    private final String                                requestTokenUri;
    private final String                                accessTokenUri;
    private final ReentrantLock                         credentialsStoreLock;
    private final HttpTransport                         httpTransport;
    private final Map<String, String>                   sharedTokenSecrets;
    private final Map<String, OAuthCredentialsResponse> credentialsStore;

    String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALhmj0yajPtj4Dug\n" +
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

    @Inject
    public BitbucketOAuthAuthenticator(@Nullable @Named("oauth.bitbucket.clientid") String clientId,
                                       @Nullable @Named("oauth.bitbucket.clientsecret") String clientSecret,
                                       @Nullable @Named("oauth.bitbucket.redirecturis") String[] redirectUris,
                                       @Nullable @Named("oauth.bitbucket.useruri") String userUri,
                                       @Nullable @Named("oauth.bitbucket.authTokenUri") String authTokenUri,
                                       @Nullable @Named("oauth.bitbucket.requestTokenUri") String requestTokenUri,
                                       @Nullable @Named("oauth.bitbucket.acessTokenuri") String accessTokenUri) throws IOException {
        super();
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.authTokenUri = authTokenUri;
        this.requestTokenUri = requestTokenUri;
        this.accessTokenUri = accessTokenUri;
        if (!isNullOrEmpty(clientId)
            && !isNullOrEmpty(clientSecret)
            && !isNullOrEmpty(authTokenUri)
            && !isNullOrEmpty(accessTokenUri)
            && redirectUris != null && redirectUris.length != 0) {

            configure(clientId, clientSecret, redirectUris, authTokenUri, accessTokenUri, new MemoryDataStoreFactory());
        }
        this.userUri = userUri;
        this.httpTransport = new NetHttpTransport();
        this.sharedTokenSecrets = new HashMap<>();
        this.credentialsStore = new HashMap<>();
        this.credentialsStoreLock = new ReentrantLock();
    }

    @Override
    public User getUser(OAuthToken accessToken) throws OAuthAuthenticationException {
        Map<String, String> params = new HashMap<>();
        params.put("Authorization", "Bearer " + accessToken.getToken());
        try {
            BitbucketUser user = doRequest(new URL(userUri), BitbucketUser.class, params);

            BitbucketEmail[] emails = doRequest(new URL("https://bitbucket.org/api/1.0/emails"), BitbucketEmail[].class, params);

            for (final BitbucketEmail oneEmail : emails) {
                if (oneEmail.isPrimary()) {
                    user.setEmail(oneEmail.getEmail());
                    break;
                }
            }
            return user;
        } catch (JsonParseException | IOException e) {
            throw new OAuthAuthenticationException(e.getMessage(), e);
        }
    }

    public OAuthToken getToken(String userId) throws IOException {
        OAuthCredentialsResponse credentials = null;
        credentialsStoreLock.lock();
        try {

            credentials = credentialsStore.get(userId);

        } finally {
            credentialsStoreLock.unlock();
        }

        if (credentials != null) {
            // Need to check if token which stored is valid for requests, then if valid - we returns it to caller
            HttpURLConnection connection = null;
            try {

                connection = (HttpURLConnection)new URL(authTokenUri).openConnection();
                connection.setInstanceFollowRedirects(false);

                final String token = credentials.token;
                final String tokenSecret = credentials.tokenSecret;
                final Map<String, String> requestParameters = emptyMap();

                connection.setRequestProperty(AUTHORIZATION,
                                              computeAuthorizationHeader(GET, authTokenUri, requestParameters, token, tokenSecret));

                if (connection.getResponseCode() == 401) {
                    return null;
                }

            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }
        return newDto(OAuthToken.class).withToken(credentials.token);
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
    public String getAuthenticateUrl(URL requestUrl, List<String> scopes) throws OAuthAuthenticationException {


        try {
            // construct the callback url
            final GenericUrl url = new GenericUrl(requestUrl);

            final OAuthGetTemporaryToken getTemporaryToken = new BitBucketOAuthGetTemporaryToken(requestTokenUri);
            getTemporaryToken.signer = getOAuthRsaSigner();
            getTemporaryToken.consumerKey = "consumer123456";
            getTemporaryToken.callback =  url.getFirst("redirect_after_login").toString() + "?state=" + URLEncoder.encode("oauth_provider=bitbucket", "UTF-8");
            getTemporaryToken.transport = httpTransport;

            final OAuthCredentialsResponse credentialsResponse = getTemporaryToken.execute();

            final OAuthAuthorizeTemporaryTokenUrl authorizeTemporaryTokenUrl = new OAuthAuthorizeTemporaryTokenUrl(authTokenUri);
            authorizeTemporaryTokenUrl.temporaryToken = credentialsResponse.token;

            sharedTokenSecrets.put(credentialsResponse.token, credentialsResponse.tokenSecret);

            return authorizeTemporaryTokenUrl.build();

        } catch (final NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new OAuthAuthenticationException(e.getMessage());
        }
    }

    public String callback(URL requestUrl, List<String> scopes) throws OAuthAuthenticationException {
        try {
            final GenericUrl callbackUrl = new GenericUrl(requestUrl.toString());

            if (callbackUrl.getFirst(OAUTH_TOKEN_PARAM_KEY) == null) {
                throw new OAuthAuthenticationException("Missing oauth_token parameter");
            }

            if (callbackUrl.getFirst(OAUTH_VERIFIER_PARAM_KEY) == null) {
                throw new OAuthAuthenticationException("Missing oauth_verifier parameter");
            }

            final String oauthTemporaryToken = (String)callbackUrl.getFirst(OAUTH_TOKEN_PARAM_KEY);

            final OAuthGetAccessToken getAccessToken = new BitBucketOAuthGetAccessToken(accessTokenUri);
            getAccessToken.consumerKey = "consumer123456";
            getAccessToken.temporaryToken = oauthTemporaryToken;
            getAccessToken.verifier = (String)callbackUrl.getFirst(OAUTH_VERIFIER_PARAM_KEY);
            getAccessToken.transport = httpTransport;
            getAccessToken.signer = getOAuthRsaSigner();

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

        } catch (final IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new OAuthAuthenticationException(e.getMessage());
        }
    }

    @Override
    public final String getOAuthProvider() {
        return "bitbucket";
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
     * @param tokenSecret
     *         the secret token.
     * @return the authorization header value, or {@code null}.
     */
    private String computeAuthorizationHeader(@NotNull final String requestMethod,
                                              @NotNull final String requestUrl,
                                              @NotNull final Map<String, String> requestParameters,
                                              @NotNull final String token,
                                              @NotNull final String tokenSecret) {

        final OAuthHmacSigner signer = new OAuthHmacSigner();
        signer.clientSharedSecret = clientSecret;
        signer.tokenSharedSecret = tokenSecret;

        final OAuthParameters oauthParameters = new OAuthParameters();
        oauthParameters.consumerKey = clientId;
        oauthParameters.signer = signer;
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

    private <O> O doRequest(URL requestUrl, Class<O> userClass, Map<String, String> params) throws IOException, JsonParseException {
        HttpURLConnection http = null;
        try {
            http = (HttpURLConnection)requestUrl.openConnection();
            http.setRequestMethod("GET");
            if (params != null) {
                for (Map.Entry<String, String> entry : params.entrySet()) {
                    http.setRequestProperty(entry.getKey(), entry.getValue());
                }
            }
            int responseCode = http.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                LOG.warn("Can not receive bitbucket user by path: {}. Response status: {}. Error message: {}",
                         requestUrl.toString(), responseCode, IoUtil.readStream(http.getErrorStream()));
                return null;
            }

            try (InputStream input = http.getInputStream()) {
                return JsonHelper.fromJson(input, userClass, null);
            }
        } finally {
            if (http != null) {
                http.disconnect();
            }
        }
    }

    public static class BitbucketEmail {
        private boolean primary;
        private String  email;

        public boolean isPrimary() {
            return primary;
        }

        @SuppressWarnings("UnusedDeclaration")
        public void setPrimary(boolean primary) {
            this.primary = primary;
        }

        public String getEmail() {
            return email;
        }

        @SuppressWarnings("UnusedDeclaration")
        public void setEmail(String email) {
            this.email = email;
        }
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
                if (oneParam.startsWith("userId" + "=")) {
                    return oneParam.substring(7, oneParam.length());
                }
            }
        }
        return null;
    }

    private OAuthRsaSigner getOAuthRsaSigner() throws NoSuchAlgorithmException, InvalidKeySpecException {
        OAuthRsaSigner oAuthRsaSigner = new OAuthRsaSigner();
        oAuthRsaSigner.privateKey = getPrivateKey(privateKey);
        return oAuthRsaSigner;
    }

    private PrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private class BitBucketOAuthGetTemporaryToken extends OAuthGetTemporaryToken {
        BitBucketOAuthGetTemporaryToken(String authorizationServerUrl) {
            super(authorizationServerUrl);
            super.usePost = true;
        }
    }

    private class BitBucketOAuthGetAccessToken extends OAuthGetAccessToken {
        BitBucketOAuthGetAccessToken(String authorizationServerUrl) {
            super(authorizationServerUrl);
            super.usePost = true;
        }
    }
}
