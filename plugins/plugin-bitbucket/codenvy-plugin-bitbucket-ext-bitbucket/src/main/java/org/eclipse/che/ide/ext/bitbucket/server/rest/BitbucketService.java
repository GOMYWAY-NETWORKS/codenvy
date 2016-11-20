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
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketPullRequest;
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketRepository;
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketRepositoryFork;
import org.eclipse.che.ide.ext.bitbucket.shared.BitbucketUser;

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
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.List;

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
    private final SshServiceClient     sshServiceClient;

    private String privateKey         = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALhmj0yajPtj4Dug\n" +
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
    private String oauth_consumer_key = "hardcoded-consumer";
    private String requestUrl         = "http://bitbucket.codenvy-stg.com:7990/plugins/servlet/oauth/request-token";

    @Inject
    public BitbucketService(@NotNull final Bitbucket bitbucket,
                            @NotNull final BitbucketKeyUploader bitbucketKeyUploader,
                            @NotNull final SshServiceClient sshServiceClient) {
        this.bitbucket = bitbucket;
        this.bitbucketKeyUploader = bitbucketKeyUploader;
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
    @Path("host")
    public String getHost() {
        return "http://bitbucket.codenvy-stg.com:7990";
    }

    @GET
    @Path("token")
    public String getToken(@QueryParam("callback") final String callback)
            throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        OAuthRsaSigner signer = new OAuthRsaSigner();
        signer.privateKey = getPrivateKey(privateKey);
        BitBucketOAuthGetTemporaryToken getTemporaryToken = new BitBucketOAuthGetTemporaryToken(requestUrl);
        getTemporaryToken.signer = signer;
        getTemporaryToken.consumerKey = oauth_consumer_key;
        getTemporaryToken.callback = callback;
        getTemporaryToken.transport = new NetHttpTransport();

        OAuthCredentialsResponse response = getTemporaryToken.execute();

        return response.token;
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
