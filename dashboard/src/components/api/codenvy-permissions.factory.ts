/*
 *  [2015] - [2016] Codenvy, S.A.
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
'use strict';

/**
 * This class is handling the permissions API
 * @author Ann Shumilova
 * @author Oleksii Orel
 */
export class CodenvyPermissions {

  /**
   * Angular promise service.
   */
  private $q: ng.IQService;

  /**
   * Angular Resource service.
   */
  private $resource: ng.resource.IResourceService;
  /**
   * Services availability to user.
   */
  private userServices: any;
  /**
   * Workspace permissions with workspace's id as a key.
   */
  private workspacePermissions: Map<string, any>;
  /**
   * Team permissions with team's id as a key.
   */
  private teamPermissions: Map<string, any>;
  /**
   * Available system permissions.
   */
  private systemPermissions: any;

  /**
   * Client to make remote permissions API calls.
   */
  private remotePermissionsAPI: ng.resource.IResourceClass<ng.resource.IResource<any>>;

  /**
   * Default constructor that is using resource
   * @ngInject for Dependency injection
   */
  constructor($q: ng.IQService, $resource: ng.resource.IResourceService) {
    this.$q = $q;
    this.$resource = $resource;

    this.workspacePermissions = new Map();
    this.teamPermissions = new Map();
    this.systemPermissions = null;

    this.userServices = {
      hasUserService: false,
      hasUserProfileService: false,
      hasAdminUserService: false,
      hasInstallationManagerService: false,
      hasLicenseService: false
    };

    // remote permissions calls
    this.remotePermissionsAPI = this.$resource('/api/permissions', {}, {
      store: {method: 'POST', url: '/api/permissions'},
      remove: {method: 'DELETE', url: '/api/permissions/:domain?instance=:instance&user=:user'},
      getSystemPermissions: {method: 'GET', url: '/api/permissions/system'},
      getPermissionsByInstance: {method: 'GET', url: '/api/permissions/:domain/all?instance=:instance', isArray: true}
    });
  }

  /**
   * Stores permissions data.
   *
   * @param data - permissions data
   * @returns {ng.IPromise<any>}
   */
  storePermissions(data: any): ng.IPromise<any> {
    let promise = this.remotePermissionsAPI.store(data).$promise;
    return promise;
  }

  /**
   * Fetch team permissions by team's id.
   *
   * @param teamId team id
   * @returns {ng.IPromise<any>}
   */
  fetchTeamPermissions(teamId: string): ng.IPromise<any> {
    let promise = this.remotePermissionsAPI.getPermissionsByInstance({domain: 'organization', instance: teamId}).$promise;
    let resultPromise = promise.then((permissions) => {
      this.teamPermissions.set(teamId, permissions);
    });

    return resultPromise;
  }

  /**
   * Returns the list of team's permissions by team's id
   *
   * @param teamId team id
   * @returns {*} list of team permissions
   */
  getTeamPermissions(teamId: string): any {
    return this.teamPermissions.get(teamId);
  }

  /**
   * Remove permissions for pointed user in pointed team.
   *
   * @param teamId team id
   * @param userId user id
   * @returns {ng.IPromise<any>} request promise
   */
  removeTeamPermissions(teamId: string, userId: string): ng.IPromise<any> {
    let promise = this.remotePermissionsAPI.remove({domain: 'organization', instance: teamId, user: userId}).$promise;
    return promise;
  }

  /**
   * Fetch workspace permissions by workspace's id.
   *
   * @param workspaceId workspace id
   * @returns {ng.IPromise<any>}
   */
  fetchWorkspacePermissions(workspaceId: string): ng.IPromise<any> {
    let promise = this.remotePermissionsAPI.getPermissionsByInstance({domain: 'workspace', instance: workspaceId}).$promise;
    let resultPromise = promise.then((permissions) => {
        this.workspacePermissions.set(workspaceId, permissions);
      });

    return resultPromise;
  }

  /**
   * Returns permissions data by workspace id
   *
   * @param workspaceId workspace id
   * @returns {ng.IPromise<any>} list of workspace permissions
   */
  getWorkspacePermissions(workspaceId: string): any {
    return this.workspacePermissions.get(workspaceId);
  }

  /**
   * Remove permissions for pointed user in pointed workspace.
   *
   * @param workspaceId workspace id
   * @param userId user id
   * @returns {ng.IPromise<any>e} request promise
   */
  removeWorkspacePermissions(workspaceId: string, userId: string): ng.IPromise<any> {
    let promise = this.remotePermissionsAPI.remove({domain: 'workspace', instance: workspaceId, user: userId}).$promise;
    return promise;
  }

  /**
   * Fetch system permissions
   *
   * @returns {ng.IPromise<any>}
   */
  fetchSystemPermissions(): ng.IPromise<any> {
    let promise = this.remotePermissionsAPI.getSystemPermissions().$promise;
    let resultPromise = promise.then((systemPermissions: any) => {
      this._updateUserServices(systemPermissions);
      this.systemPermissions = systemPermissions;
    });

    return resultPromise;
  }

  _updateUserServices(systemPermissions: any): void {
    let isManageUsers = systemPermissions && systemPermissions.actions.includes('manageUsers');
    let isManageCodenvy = systemPermissions && systemPermissions.actions.includes('manageCodenvy');

    this.userServices.hasUserService = isManageUsers;
    this.userServices.hasUserProfileService = isManageUsers;
    this.userServices.hasAdminUserService = isManageUsers;
    this.userServices.hasInstallationManagerService = isManageCodenvy;
    this.userServices.hasLicenseService = isManageCodenvy;
  }

  getSystemPermissions(): any {
    return this.systemPermissions;
  }

  getUserServices(): any {
    return this.userServices;
  }
}
