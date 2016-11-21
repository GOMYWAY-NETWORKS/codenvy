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

import {CodenvyTeamRoles} from './codenvy-team-roles';

/**
 * This class is handling the interactions with Team management API.
 *
 * @author Ann Shumilova
 */
export class CodenvyTeam {
  /**
   * Angular Resource service.
   */
  private $resource: ng.resource.IResourceService;
  private lodash: any;
  /**
   * Teams map by team's id.
   */
  private teamsMap : Map<string, any> = new Map();
  /**
   * Array of teams.
   */
  private teams : any = [];
  /**
   * The registry for managing available namespaces.
   */
  private cheNamespaceRegistry : any;
  /**
   * Client for requesting Team API.
   */
  private remoteTeamAPI: ng.resource.IResourceClass<ng.resource.IResource<any>>;

  /**
   * Default constructor that is using resource
   * @ngInject for Dependency injection
   */
  constructor($resource: ng.resource.IResourceService, lodash: any, cheNamespaceRegistry: any) {
    this.$resource = $resource;
    this.lodash = lodash;
    this.cheNamespaceRegistry = cheNamespaceRegistry;

    this.remoteTeamAPI = $resource('/api/organization', {}, {
      getTeams: {method: 'GET', url: '/api/organization', isArray: true},
      createTeam: {method: 'POST', url: '/api/organization'},
      deleteTeam: {method: 'DELETE', url: '/api/organization/:id'},
      updateTeam: {method: 'POST', url: '/api/organization/:id'},
      findTeam: {method: 'GET', url: '/api/organization/find?name=:teamName'}
    });
  }

  /**
   * Request the list of available teams.
   *
   * @returns {PromiseLike<TResult>|Promise<TResult>}
   */
  fetchTeams(): ng.IPromise<any> {
    let promise = this.remoteTeamAPI.getTeams().$promise;

    // process the result into map and array:
    let resultPromise = promise.then((teams: any) => {
      this.teamsMap = new Map();
      this.teams = [];
      this.cheNamespaceRegistry.getNamespaces().length = 0;

      teams.forEach((team : any) => {
        this.teamsMap.set(team.id, team);
        this.teams.push(team);
        this.cheNamespaceRegistry.getNamespaces().push(team.name);
      });
    });

    return resultPromise;
  }

  /**
   * Returns the array of teams.
   *
   * @returns {Array<any>} the array of teams
   */
  getTeams(): Array<any> {
    return this.teams;
  }

  /**
   * Requests team by it's name.
   *
   * @param name the team's name
   * @returns {ng.IPromise<any>} result promise
   */
  fetchTeamByName(name: string): ng.IPromise<any> {
    let promise = this.remoteTeamAPI.findTeam({'teamName' : name}).$promise;
    return promise;
  }

  /**
   * Returns team by it's name.
   *
   * @param name team's name
   * @returns {any} team or <code>null</code> if not found
   */
  getTeamByName(name: string): any {
    for (let i = 0; i < this.teams.length; i++) {
      if (this.teams[i].name === name) {
        return this.teams[i];
      }
    };

    return null;
  }

  /**
   * Creates new team with pointed name.
   *
   * @param name the name of the team to be created
   * @returns {ng.IPromise<any>} result promise
   */
  createTeam(name: string): ng.IPromise<any> {
    let data = {'name' : name};
    let promise = this.remoteTeamAPI.createTeam(data).$promise;
    return promise;
  }

  /**
   * Delete team by pointed id.
   *
   * @param id team's id to be deleted
   * @returns {ng.IPromise<any>} result promise
   */
  deleteTeam(id: string): ng.IPromise<any> {
    let promise = this.remoteTeamAPI.deleteTeam({'id' : id}).$promise;
    return promise;
  }

  /**
   * Update team's info.
   *
   * @param team the team info to be updated
   * @returns {ng.IPromise<any>} result promise
   */
  updateTeam(team: any): ng.IPromise<any> {
    let promise = this.remoteTeamAPI.updateTeam({'id' : team.id}, team).$promise;
    return promise;
  }

  /**
   * Forms the list of roles based on the list of actions
   *
   * @param actions array of actions
   * @returns {Array<any>} array of roles
   */
  getRolesFromActions(actions: Array<string>): Array<any> {
    let roles = [];
    let teamRoles = CodenvyTeamRoles.getValues();
    teamRoles.forEach((role: any) => {
      if (this.lodash.difference(role.actions, actions).length === 0) {
        roles.push(role);
      }
    });
    return roles;
  }

  /**
   * Forms the list actions based on the list of roles.
   *
   * @param roles array of roles
   * @returns {Array<string>} actions array
   */
  getActionsFromRoles(roles: Array<any>): Array<string> {
    let actions = [];
    roles.forEach((role: any) => {
      actions = actions.concat(role.actions);
    });

    return actions;
  }
}
