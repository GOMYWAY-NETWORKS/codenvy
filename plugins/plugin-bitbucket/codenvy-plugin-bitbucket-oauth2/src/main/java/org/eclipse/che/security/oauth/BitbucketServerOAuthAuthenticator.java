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
import com.google.api.client.auth.oauth.OAuthParameters;
import com.google.api.client.auth.oauth.OAuthRsaSigner;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Base64;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import com.google.inject.name.Named;

import org.eclipse.che.api.auth.shared.dto.OAuthToken;
import org.eclipse.che.commons.annotation.Nullable;
import org.eclipse.che.security.oauth.shared.User;

import javax.validation.constraints.NotNull;
import java.io.IOException;
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

import static java.net.URLDecoder.decode;
import static javax.ws.rs.HttpMethod.GET;
import static javax.ws.rs.core.HttpHeaders.AUTHORIZATION;
import static org.eclipse.che.dto.server.DtoFactory.newDto;

/**
 * OAuth authentication for Bitbucket account.
 *
 * @author Igor Vinokur
 */
@Singleton
public class BitbucketServerOAuthAuthenticator extends OAuthAuthenticator {

    private static final String STATE_PARAM_KEY          = "state";
    private static final String OAUTH_TOKEN_PARAM_KEY    = "oauth_token";
    private static final String OAUTH_VERIFIER_PARAM_KEY = "oauth_verifier";

    private final String                                authTokenUri;
    private final String                                requestTokenUri;
    private final String                                privateKey;
    private final String                                consumerKey;
    private final String                                accessTokenUri;
    private final String                                verifyAccessTokenUri;
    private final ReentrantLock                         credentialsStoreLock;
    private final HttpTransport                         httpTransport;
    private final Map<String, OAuthCredentialsResponse> credentialsStore;

    @Inject
    public BitbucketServerOAuthAuthenticator(@Nullable @Named("oauth.bitbucket.verifyaccesstokenuri") String verifyAccessTokenUri,
                                             @Nullable @Named("oauth.bitbucket.authtokenuri") String authTokenUri,
                                             @Nullable @Named("oauth.bitbucket.requesttokenuri") String requestTokenUri,
                                             @Nullable @Named("oauth.bitbucket.privatekey") String privateKey,
                                             @Nullable @Named("oauth.bitbucket.consumerkey") String consumerKey,
                                             @Nullable @Named("oauth.bitbucket.acessTokenuri") String accessTokenUri) throws IOException {
        this.authTokenUri = authTokenUri;
        this.requestTokenUri = requestTokenUri;
        this.privateKey = privateKey;
        this.consumerKey = consumerKey;
        this.accessTokenUri = accessTokenUri;
        this.httpTransport = new NetHttpTransport();
        this.credentialsStore = new HashMap<>();
        this.credentialsStoreLock = new ReentrantLock();
        this.verifyAccessTokenUri = verifyAccessTokenUri;
    }

    @Override
    public User getUser(OAuthToken accessToken) {
        return null;
    }

    @Override
    public OAuthToken getToken(String userId) throws IOException {
        OAuthCredentialsResponse credentials;
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

                connection = (HttpURLConnection)new URL(verifyAccessTokenUri).openConnection();
                connection.setInstanceFollowRedirects(false);

                final String token = credentials.token;

                connection.setRequestProperty(AUTHORIZATION,
                                              computeAuthorizationHeader(GET, verifyAccessTokenUri, token));

                if (connection.getResponseCode() == 401) {
                    return null;
                }

            } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            } finally {
                if (connection != null) {
                    connection.disconnect();
                }
            }
        }
        return newDto(OAuthToken.class).withToken(credentials.token);
    }

    @Override
    public String getAuthenticateUrl(URL requestUrl, List<String> scopes) throws OAuthAuthenticationException {


        try {
            // construct the callback url
            final GenericUrl url = new GenericUrl(requestUrl);

            String callbackUrl = url.getFirst("callbackUrl").toString();
            String userId = url.getFirst("userId").toString();
            String provider = url.getFirst("oauth_provider").toString();
            String redirectUrl = url.getFirst("redirect_after_login").toString();

            final OAuthGetTemporaryToken getTemporaryToken = new BitBucketOAuthGetTemporaryToken(requestTokenUri);
            getTemporaryToken.signer = getOAuthRsaSigner();
            getTemporaryToken.consumerKey = consumerKey;
            getTemporaryToken.callback = callbackUrl + "?state=" + URLEncoder.encode("oauth_provider=" + provider +
                                                                                     "&userId=" + userId +
                                                                                     "&redirect_after_login=" + redirectUrl, "UTF-8");
            getTemporaryToken.transport = httpTransport;

            final OAuthCredentialsResponse credentialsResponse = getTemporaryToken.execute();

            final OAuthAuthorizeTemporaryTokenUrl authorizeTemporaryTokenUrl = new OAuthAuthorizeTemporaryTokenUrl(authTokenUri);
            authorizeTemporaryTokenUrl.temporaryToken = credentialsResponse.token;

            return authorizeTemporaryTokenUrl.build();

        } catch (final NoSuchAlgorithmException | InvalidKeySpecException | IOException e) {
            throw new OAuthAuthenticationException(e.getMessage());
        }
    }

    @Override
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
            getAccessToken.consumerKey = consumerKey;
            getAccessToken.temporaryToken = oauthTemporaryToken;
            getAccessToken.verifier = (String)callbackUrl.getFirst(OAUTH_VERIFIER_PARAM_KEY);
            getAccessToken.transport = httpTransport;
            getAccessToken.signer = getOAuthRsaSigner();

            final OAuthCredentialsResponse credentials = getAccessToken.execute();
            final String state = (String)callbackUrl.getFirst(STATE_PARAM_KEY);

            String userId = getUserFromStateParameter(state);

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
        return "bitbucket-server";
    }

    /**
     * Compute the Authorization header to sign the OAuth 1 request.
     *
     * @param requestMethod
     *         the HTTP request method.
     * @param requestUrl
     *         the HTTP request url with encoded query parameters.
     * @param token
     *         the token.
     * @return the authorization header value, or {@code null}.
     */
    private String computeAuthorizationHeader(@NotNull final String requestMethod,
                                              @NotNull final String requestUrl,
                                              @NotNull final String token) throws InvalidKeySpecException, NoSuchAlgorithmException {

        final OAuthParameters oauthParameters = new OAuthParameters();
        oauthParameters.consumerKey = consumerKey;
        oauthParameters.signer = getOAuthRsaSigner();
        oauthParameters.token = token;
        oauthParameters.version = "1.0";

        oauthParameters.computeNonce();
        oauthParameters.computeTimestamp();

        final GenericUrl genericRequestUrl = new GenericUrl(requestUrl);

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
