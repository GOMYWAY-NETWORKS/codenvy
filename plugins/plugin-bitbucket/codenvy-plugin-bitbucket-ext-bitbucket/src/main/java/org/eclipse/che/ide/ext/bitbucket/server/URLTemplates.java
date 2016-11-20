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

import com.google.inject.Singleton;

import static java.lang.String.format;
import static java.util.Objects.requireNonNull;

/**
 * Defines URL templates for BitBucket.
 *
 * @author Igor Vinokur
 */
@Singleton
public class URLTemplates {

    private static final String SERVERHOST = "http://bitbucket.codenvy-stg.com:7990/";
    private static final String HOST       = "https://api.bitbucket.org/2.0/";

    private static final String REPOSITORY                = isHosted() ? "/repositories/%s/%s" : "/projects/~%s/repos/%s";
    private static final String REPOSITORIES              = "/%s/_apis/git/repositories";
    private static final String PULL_REQUESTS             = "/_apis/git/repositories/%s/pullrequests";
    private static final String PULL_REQUEST              = "/_apis/git/repositories/%s/pullrequests/%s";
    private static final String PROJECT_REPO_PULL_REQUEST = "/%s/_apis/git/repositories/%s/pullrequests/%s";

    public static final String PROFILE = "/_apis/profile/profiles/me";

    private static final String PROJECT_HTTP_REMOTE_URL        = "/_git/%s";
    private static final String PROJECT_REPO_HTTP_REMOTE_URL   = "/%s/_git/%s";
    private static final String PROJECT_HTML_PULL_REQUEST      = "/_git/%s/pullrequest/%s";
    private static final String PROJECT_REPO_HTML_PULL_REQUEST = "/%s/_git/%s/pullrequest/%s";

    /**
     * Returns repository url.
     *
     * @param project
     *         team project id or name
     * @param repoName
     *         id or name of the repository
     * @throws IllegalArgumentException
     *         when either {@code project} or {@code repoName} is null or empty
     */
    public String repositoryUrl(String project, String repoName) {
        requireNonNull(project, "Project name required");
        requireNonNull(repoName, "Repository name required");

        return format(REPOSITORY, project, repoName);
    }

    public String userUrl(String username) {
        requireNonNull(username, "User name required");

        return SERVERHOST + "rest/api/latest/users/" + username;
    }

    private static boolean isHosted() {
        return false;
    }

//    /**
//     * Returns repositories url.
//     *
//     * @param project
//     *         team project id or name
//     * @throws IllegalArgumentException
//     *         when {@code project} is null or empty
//     */
//    public String repositoriesUrl(String account, String collection, String project) {
//        Objects.requireNonNull(project, "Project required");
//        return getTeamBaseUrl(account, collection) + format(REPOSITORIES, project) + getApiVersion();
//    }
//
//    /**
//     * Returns the url for pull requests.
//     *
//     * @param repoId
//     *         id of the repository
//     * @throws IllegalArgumentException
//     *         when {@code repository} is null or empty
//     */
//    public String pullRequestsUrl(String account, String collection, String repoId) {
//        Objects.requireNonNull(repoId, "Repository id required");
//        return getTeamBaseUrl(account, collection) + format(PULL_REQUESTS, repoId) + getApiVersion();
//    }
//
//    /**
//     * Returns pull request url.
//     *
//     * @param repoId
//     *         id of the repository
//     * @param pullRequest
//     *         id of the pull request
//     * @throws IllegalArgumentException
//     *         when either {@code repository} or {@code pullRequest} is null or empty
//     */
//    public String pullRequestUrl(String account, String collection, String repoId, String pullRequest) {
//        Objects.requireNonNull(repoId, "Repository required");
//        Objects.requireNonNull(pullRequest, "Pull request required");
//        return getTeamBaseUrl(account, collection) + format(PULL_REQUEST, repoId, pullRequest) + getApiVersion();
//    }
//
//    /**
//     * Returns pull request url.
//     *
//     * @param projectName
//     *         the name of the project
//     * @param repositoryName
//     *         the name of the repository
//     * @param pullRequestId
//     *         the id of the pull request
//     */
//    public String pullRequestUrl(String account, String collection, String projectName, String repositoryName, String pullRequestId) {
//        Objects.requireNonNull(projectName, "Project name required");
//        Objects.requireNonNull(repositoryName, "Repository name required");
//        Objects.requireNonNull(pullRequestId, "Pull request id required");
//        return getTeamBaseUrl(account, collection) + format(PROJECT_REPO_PULL_REQUEST, projectName, repositoryName, pullRequestId) + getApiVersion();
//    }
//
//    /**
//     * Returns pull request html url.
//     *
//     * @param projectName
//     *         the name of the project
//     * @param repositoryName
//     *         the name of the repository
//     * @param pullRequestId
//     *         the id of the pull request
//     */
//    public String pullRequestHtmlUrl(String account, String collection, String projectName, String repositoryName, String pullRequestId) {
//        Objects.requireNonNull(projectName, "Project name required");
//        Objects.requireNonNull(repositoryName, "Repository name required");
//        Objects.requireNonNull(pullRequestId, "Pull request id required");
//        String pullRequestUrl;
//        if (projectName.equals(repositoryName)) {
//            pullRequestUrl = getTeamBaseUrl(account, collection) + format(PROJECT_HTML_PULL_REQUEST, projectName, pullRequestId);
//        } else {
//            pullRequestUrl = getTeamBaseUrl(account, collection) + format(PROJECT_REPO_HTML_PULL_REQUEST, projectName, repositoryName, pullRequestId);
//        }
//        return pullRequestUrl;
//    }
}
