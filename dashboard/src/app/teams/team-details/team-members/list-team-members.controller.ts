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
import {CodenvyTeam} from '../../../../components/api/codenvy-team.factory';
import {CodenvyPermissions} from '../../../../components/api/codenvy-permissions.factory';
import {CodenvyUser} from '../../../../components/api/codenvy-user.factory';

/**
 * @ngdoc controller
 * @name teams.members:ListTeamMembersController
 * @description This class is handling the controller for the list of team's members.
 * @author Ann Shumilova
 */
export class ListTeamMembersController {

  /**
   * Team API interaction.
   */
  private codenvyTeam: CodenvyTeam;
  /**
   * User API interaction.
   */
  private codenvyUser: CodenvyUser;
  /**
   * Permissions API interaction.
   */
  private codenvyPermissions: CodenvyPermissions;
  /**
   * Service for displaying dialogs.
   */
  private $mdDialog: angular.material.IDialogService;
  /**
   * Notifications service.
   */
  private cheNotification: any;
  /**
   * Promises service.
   */
  private $q: ng.IQService;
  /**
   * Team's members list.
   */
  private members: Array<any>;
  /**
   * Loading state of the page.
   */
  private isLoading: boolean;
  /**
   * Filter for members list.
   */
  private memberFilter: any;
  /**
   * Selected status of members in list.
   */
  private membersSelectedStatus: any;
  /**
   * Bulk operation state.
   */
  private isBulkChecked: boolean;
  /**
   * No selected members state.
   */
  private isNoSelected: boolean;
  /**
   * All selected members state.
   */
  private isAllSelected: boolean;

  /**
   * Current team (comes from directive's scope).
   */
  private team: any;

  /**
   * Default constructor that is using resource
   * @ngInject for Dependency injection
   */
  constructor(codenvyTeam: CodenvyTeam, codenvyPermissions: CodenvyPermissions, codenvyUser: CodenvyUser,
              $mdDialog: angular.material.IDialogService, $q: ng.IQService, cheNotification: any) {
    this.codenvyTeam = codenvyTeam;
    this.codenvyPermissions = codenvyPermissions;
    this.codenvyUser = codenvyUser;
    this.$mdDialog = $mdDialog;
    this.$q = $q;
    this.cheNotification = cheNotification;

    this.members = [];
    this.isLoading = true;

    this.memberFilter = {name: ''};

    this.membersSelectedStatus = {};
    this.isBulkChecked = false;
    this.isNoSelected = true;
    this.fetchMembers();
  }

  /**
   * Fetches the lis of team members.
   */
  fetchMembers(): void {
    this.isLoading = true;

    this.codenvyPermissions.fetchTeamPermissions(this.team.id).then(() => {
      this.isLoading = false;
      this.formUserList();
    }, (error: any) => {
      this.isLoading = false;
      if (error.status === 304) {
        this.formUserList();
      } else {
        this.cheNotification.showError(error.data && error.data.message ? error.data.message : 'Failed to retrieve team permissions.');
      }
    });
  }

  /**
   * Combines permissions and users data in one list.
   */
  formUserList(): void {
    let permissions = this.codenvyPermissions.getTeamPermissions(this.team.id);
    this.members = [];

    permissions.forEach((permission) => {
      let userId = permission.userId;
      let user = this.codenvyUser.getUserFromId(userId);
      if (user) {
        this.formUserItem(user, permission);
      } else {
        this.codenvyUser.fetchUserId(userId).then(() => {
          this.formUserItem(this.codenvyUser.getUserFromId(userId), permission);
        });
      }
    });
  }

  /**
   * Forms item to display with permissions and user data.
   *
   * @param user user data
   * @param permissions permissions data
   */
  formUserItem(user: any, permissions: any): void {
    let userItem = angular.copy(user);
    userItem.permissions = permissions;
    this.members.push(userItem);
  }

  /**
   * Return <code>true</code> if all members in list are checked.
   * @returns {boolean}
   */
  isAllMembersSelected(): boolean {
    return this.isAllSelected;
  }

  /**
   * Returns <code>true</code> if all members in list are not checked.
   * @returns {boolean}
   */
  isNoMemberSelected(): boolean {
    return this.isNoSelected;
  }

  /**
   * Make all members in list selected.
   */
  selectAllMembers(): void {
    this.members.forEach((member: any) => {
      this.membersSelectedStatus[member.id] = true;
    });
  }

  /**
   * Make all members in list deselected.
   */
  deselectAllMembers(): void {
    this.members.forEach((member: any) => {
      this.membersSelectedStatus[member.id] = false;
    });
  }

  /**
   * Change bulk selection value.
   */
  changeBulkSelection(): void {
    if (this.isBulkChecked) {
      this.deselectAllMembers();
      this.isBulkChecked = false;
    } else {
      this.selectAllMembers();
      this.isBulkChecked = true;
    }
    this.updateSelectedStatus();
  }

  /**
   * Update members selected status.
   */
  updateSelectedStatus(): void {
    this.isNoSelected = true;
    this.isAllSelected = true;

    Object.keys(this.membersSelectedStatus).forEach((key) => {
      if (this.membersSelectedStatus[key]) {
        this.isNoSelected = false;
      } else {
        this.isAllSelected = false;
      }
    });

    if (this.isNoSelected) {
      this.isBulkChecked = false;
      return;
    }

    if (this.isAllSelected) {
      this.isBulkChecked = true;
    }
  }

  /**
   * Remove all selected members.
   */
  removeSelectedMembers(): void {
    let membersSelectedStatusKeys = Object.keys(this.membersSelectedStatus);
    let checkedKeys = [];

    if (!membersSelectedStatusKeys.length) {
      this.cheNotification.showError('No such developers.');
      return;
    }

    membersSelectedStatusKeys.forEach((key) => {
      if (this.membersSelectedStatus[key] === true) {
        checkedKeys.push(key);
      }
    });

    if (!checkedKeys.length) {
      this.cheNotification.showError('No such developers.');
      return;
    }

    let confirmationPromise = this.showDeleteMembersConfirmation(checkedKeys.length);
    confirmationPromise.then(() => {
      let removalError;
      let removeMembersPromises = [];

      checkedKeys.forEach((id : string) => {
        this.membersSelectedStatus[id] = false;
        let promise = this.codenvyPermissions.removeTeamPermissions(this.team.id, id).then(() => {},
          (error: any) => {
            removalError = error;
        });
        removeMembersPromises.push(promise);
      });

      this.$q.all(removeMembersPromises).finally(() => {
        this.fetchMembers();
        this.updateSelectedStatus();
        if (removalError) {
          this.cheNotification.showError(removalError.data && removalError.data.message ? removalError.data.message : 'User removal failed.');
        }
      });
    });
  }

  /**
   * Removes user permissions for current team
   *
   * @param user user
   */
  removePermissions(user: any) {
    this.isLoading = true;
    this.codenvyPermissions.removeTeamPermissions(user.permissions.instanceId, user.id).then(() => {
      this.fetchMembers();
    }, (error: any) => {
      this.isLoading = false;
      this.cheNotification.showError(error.data && error.data.message ? error.data.message : 'Failed to remove user ' + user.email + ' permissions.');
    });
  }

  /**
   * Show confirmation popup before members removal
   * @param numberToDelete
   * @returns {*}
   */
  showDeleteMembersConfirmation(numberToDelete: number) {
    let confirmTitle = 'Would you like to remove ';
    if (numberToDelete > 1) {
      confirmTitle += 'these ' + numberToDelete + ' developers?';
    } else {
      confirmTitle += 'the selected developer?';
    }
    let confirm = this.$mdDialog.confirm()
      .title(confirmTitle)
      .ariaLabel('Remove members')
      .ok('Delete!')
      .cancel('Cancel')
      .clickOutsideToClose(true);

    return this.$mdDialog.show(confirm);
  }
}
