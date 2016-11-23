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

import com.google.api.client.auth.oauth.OAuthCredentialsResponse;
import com.google.api.client.auth.oauth.OAuthGetTemporaryToken;
import com.google.api.client.auth.oauth.OAuthRsaSigner;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.util.Base64;

import org.eclipse.che.api.core.NotFoundException;
import org.eclipse.che.api.core.ServerException;
import org.eclipse.che.api.core.UnauthorizedException;
import org.eclipse.che.api.git.exception.GitException;
import org.eclipse.che.api.ssh.server.SshServiceClient;
import org.eclipse.che.api.ssh.shared.dto.GenerateSshPairRequest;
import org.eclipse.che.api.ssh.shared.model.SshPair;
import org.eclipse.che.ide.ext.bitbucket.server.Bitbucket;
import org.eclipse.che.ide.ext.bitbucket.server.BitbucketException;
import org.eclipse.che.ide.ext.bitbucket.server.BitbucketKeyUploader;
import org.eclipse.che.ide.ext.bitbucket.server.BitbucketServerOAuthAuthenticator;
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketPullRequest;
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketRepository;
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketRepositoryFork;
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketUser;
import org.eclipse.che.security.oauth.OAuthAuthenticationException;
import org.eclipse.che.security.oauth.OAuthAuthenticator;

import javax.inject.Inject;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static javax.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.eclipse.che.dto.server.DtoFactory.newDto;

/**
 * REST service for Bitbucket.
 *
 * @author Kevin Pollet
 */
@Path("/bitbucket")
public class BitbucketService {
    private final Bitbucket            bitbucket;
    private final BitbucketKeyUploader bitbucketKeyUploader;
    private final BitbucketServerOAuthAuthenticator oAuthAuthenticator;
    private final SshServiceClient sshServiceClient;

    @Inject
    public BitbucketService(@NotNull final Bitbucket bitbucket,
                            @NotNull final BitbucketKeyUploader bitbucketKeyUploader,
                            @NotNull final BitbucketServerOAuthAuthenticator oAuthAuthenticator,
                            @NotNull final SshServiceClient sshServiceClient) {
        this.bitbucket = bitbucket;
        this.bitbucketKeyUploader = bitbucketKeyUploader;
        this.oAuthAuthenticator = oAuthAuthenticator;
        this.sshServiceClient = sshServiceClient;
    }

    /**
     * @see org.eclipse.che.ide.ext.bitbucket.server.Bitbucket#getUser(String)
     */
    @GET
    @Path("user")
    @Produces(APPLICATION_JSON)
    public BitbucketUser getUser(@QueryParam("username") final String username) throws IOException, BitbucketException, ServerException {
        return bitbucket.getUser(username);
    }

    @GET
    @Path("authenticate")
    public Response authenticate(@Context UriInfo uriInfo)
            throws OAuthAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException {
        final URL requestUrl = getRequestUrl(uriInfo);
        final String authUrl = oAuthAuthenticator.getAuthenticateUrl(requestUrl);

        return Response.temporaryRedirect(URI.create(authUrl)).build();
    }

    protected URL getRequestUrl(UriInfo uriInfo) {
        try {
            return uriInfo.getRequestUri().toURL();
        } catch (MalformedURLException e) {
            // should never happen
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    @GET
    @Path("callback")
    public Response callback(@Context UriInfo uriInfo)
            throws OAuthAuthenticationException, InvalidKeySpecException, NoSuchAlgorithmException {
        final URL requestUrl = getRequestUrl(uriInfo);
        final Map<String, List<String>> params = getRequestParameters(getState(requestUrl));

        oAuthAuthenticator.callback(requestUrl);

        final String redirectAfterLogin = getParameter(params, "redirect_after_login");
        return Response.temporaryRedirect(URI.create(redirectAfterLogin)).build();
    }

    protected String getParameter(Map<String, List<String>> params, String name) {
        List<String> l = params.get(name);
        if (!(l == null || l.isEmpty())) {
            return l.get(0);
        }
        return null;
    }

    protected String getState(URL requestUrl) {
        final String query = requestUrl.getQuery();
        if (!(query == null || query.isEmpty())) {
            int start = query.indexOf("state=");
            if (start < 0) {
                return null;
            }
            int end = query.indexOf('&', start);
            if (end < 0) {
                end = query.length();
            }
            return query.substring(start + 6, end);
        }
        return null;
    }

    protected Map<String, List<String>> getRequestParameters(String state) {
        Map<String, List<String>> params = new HashMap<>();
        if (!(state == null || state.isEmpty())) {
            String decodedState;
            try {
                decodedState = URLDecoder.decode(state, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                // should never happen, UTF-8 supported.
                throw new RuntimeException(e.getMessage(), e);
            }

            for (String pair : decodedState.split("&")) {
                if (!pair.isEmpty()) {
                    String name;
                    String value;
                    int eq = pair.indexOf('=');
                    if (eq < 0) {
                        name = pair;
                        value = "";
                    } else {
                        name = pair.substring(0, eq);
                        value = pair.substring(eq + 1);
                    }

                    List<String> l = params.computeIfAbsent(name, k -> new ArrayList<>());
                    l.add(value);
                }
            }
        }
        return params;
    }

    @GET
    @Path("host")
    public String getHost() {
        return "http://bitbucket.codenvy-stg.com:7990";
    }

    private PrivateKey getPrivateKey(String privateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] privateKeyBytes = Base64.decodeBase64(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * @see org.eclipse.che.ide.ext.bitbucket.server.Bitbucket#getRepository(String, String)
     */
    @GET
    @Path("repositories/{owner}/{repositorySlug}")
    @Produces(APPLICATION_JSON)
    public BitbucketRepository getRepository(@PathParam("owner") final String owner,
                                             @PathParam("repositorySlug") final String repositorySlug)
            throws IOException, BitbucketException, ServerException {

        return bitbucket.getRepository(owner, repositorySlug);
    }

    /**
     * @see org.eclipse.che.ide.ext.bitbucket.server.Bitbucket#getRepositoryForks(String, String)
     */
    @GET
    @Path("repositories/{owner}/{repositorySlug}/forks")
    @Produces(APPLICATION_JSON)
    public List<BitbucketRepository> getRepositoryForks(@PathParam("owner") final String owner,
                                                        @PathParam("repositorySlug") final String repositorySlug)
            throws IOException, BitbucketException, ServerException {

        return bitbucket.getRepositoryForks(owner, repositorySlug);
    }

    /**
     * @see org.eclipse.che.ide.ext.bitbucket.server.Bitbucket#forkRepository(String, String, String, boolean)
     */
    @POST
    @Path("repositories/{owner}/{repositorySlug}/fork")
    @Produces(APPLICATION_JSON)
    public BitbucketRepositoryFork forkRepository(@PathParam("owner") final String owner,
                                                  @PathParam("repositorySlug") final String repositorySlug,
                                                  @QueryParam("forkName") final String forkName,
                                                  @QueryParam("isForkPrivate") @DefaultValue("false") final boolean isForkPrivate)
            throws IOException, BitbucketException, ServerException {

        return bitbucket.forkRepository(owner, repositorySlug, forkName, isForkPrivate);
    }

    /**
     * @see org.eclipse.che.ide.ext.bitbucket.server.Bitbucket#getRepositoryPullRequests(String, String)
     */
    @GET
    @Path("repositories/{owner}/{repositorySlug}/pullrequests")
    @Produces(APPLICATION_JSON)
    public List<BitbucketPullRequest> getRepositoryPullRequests(@PathParam("owner") final String owner,
                                                                @PathParam("repositorySlug") final String repositorySlug)
            throws IOException, BitbucketException, ServerException {

        return bitbucket.getRepositoryPullRequests(owner, repositorySlug);
    }

    /**
     * @see org.eclipse.che.ide.ext.bitbucket.server.Bitbucket#openPullRequest(String, String, org.eclipse.che.ide.ext.bitbucket.shared.BitbucketPullRequest)
     */
    @POST
    @Path("repositories/{owner}/{repositorySlug}/pullrequests")
    @Consumes(APPLICATION_JSON)
    @Produces(APPLICATION_JSON)
    public BitbucketPullRequest openPullRequest(@PathParam("owner") final String owner,
                                                @PathParam("repositorySlug") final String repositorySlug,
                                                BitbucketPullRequest pullRequest)
            throws IOException, BitbucketException, ServerException {

        return bitbucket.openPullRequest(owner, repositorySlug, pullRequest);
    }

    @POST
    @Path("ssh-keys")
    public void generateAndUploadSSHKey() throws ServerException, UnauthorizedException {
        final String host = "bitbucket.org";
        SshPair sshPair = null;
        try {
            sshPair = sshServiceClient.getPair("git", host);
        } catch (NotFoundException ignored) {
        }

        if (sshPair != null) {
            if (sshPair.getPublicKey() == null) {
                try {
                    sshServiceClient.removePair("git", host);
                } catch (NotFoundException ignored) {
                }

                sshPair = sshServiceClient.generatePair(newDto(GenerateSshPairRequest.class).withService("git")
                                                                                            .withName(host));
            }
        } else {
            sshPair = sshServiceClient.generatePair(newDto(GenerateSshPairRequest.class).withService("git")
                                                                                        .withName(host));
        }

        // update public key
        try {
            bitbucketKeyUploader.uploadKey(sshPair.getPublicKey());
        } catch (final IOException e) {
            throw new GitException(e);
        }
    }

    private class BitBucketOAuthGetTemporaryToken extends OAuthGetTemporaryToken {
        BitBucketOAuthGetTemporaryToken(String authorizationServerUrl) {
            super(authorizationServerUrl);
            super.usePost = true;
        }
    }
}
