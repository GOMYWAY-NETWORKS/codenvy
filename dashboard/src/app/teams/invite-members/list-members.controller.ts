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
import {CodenvyTeamRoles} from '../../../components/api/codenvy-team-roles';
import {CodenvyTeam} from '../../../components/api/codenvy-team.factory';

/**
 * @ngdoc controller
 * @name teams.invite.members:ListMembersController
 * @description This class is handling the controller for the list of invited members.
 * @author Ann Shumilova
 */
export class ListMembersController {

  /**
   * Team API interaction.
   */
  private codenvyTeam: CodenvyTeam;
  /**
   * Lodash library.
   */
  private lodash: any;
  /**
   * Service for displaying dialogs.
   */
  private $mdDialog: angular.material.IDialogService;
  /**
   * No members selected.
   */
  private isNoSelected: boolean;
  /**
   * Bulk operation checked state.
   */
  private isBulkChecked: boolean;
  /**
   * Status of selected members.
   */
  private membersSelectedStatus: any;
  /**
   * Number of selected members.
   */
  private membersSelectedNumber: number;
  /**
   * Members order by value.
   */
  private membersOrderBy: string;
  /**
   * Member roles by email.
   */
  private memberRoles: any;
  /**
   * List of members to be invited.
   */
  private members: Array<any>;

  /**
   * Default constructor that is using resource
   * @ngInject for Dependency injection
   */
  constructor($mdDialog: angular.material.IDialogService, lodash: any, codenvyTeam: CodenvyTeam) {
    this.$mdDialog = $mdDialog;
    this.lodash = lodash;
    this.codenvyTeam = codenvyTeam;

    this.isNoSelected = true;
    this.isBulkChecked = false;
    this.membersSelectedStatus = {};
    this.membersSelectedNumber = 0;
    this.membersOrderBy = 'email';
    this.memberRoles = {};
  }

  /**
   * Forms the list of members.
   */
  buildMembersList(): void {
    this.memberRoles = {};
    this.members.forEach((member: any) => {
      let roles = {
        isManageTeam: member.roles.indexOf(CodenvyTeamRoles.MANAGE_TEAM) >= 0,
        isManageResources: member.roles.indexOf(CodenvyTeamRoles.MANAGE_RESOURCES) >= 0,
        isManageWorkspaces: member.roles.indexOf(CodenvyTeamRoles.MANAGE_WORKSPACES) >= 0,
        isCreateWorkspaces: member.roles.indexOf(CodenvyTeamRoles.CREATE_WORKSPACES) >= 0
      };
      this.memberRoles[member.email] = roles;
    });
  }

  /**
   * Handler the roles changes and updates member's roles.
   *
   * @param member member
   */
  onRolesChanged(member: any): void {
    let roles = [];
    let rolesInfo = this.memberRoles[member.email];
    if (rolesInfo.isManageTeam) {
      roles.push(CodenvyTeamRoles.MANAGE_TEAM);
    }

    if (rolesInfo.isManageResources) {
      roles.push(CodenvyTeamRoles.MANAGE_RESOURCES);
    }

    if (rolesInfo.isManageWorkspaces) {
      roles.push(CodenvyTeamRoles.MANAGE_WORKSPACES);
    }

    if (rolesInfo.isCreateWorkspaces) {
      roles.push(CodenvyTeamRoles.CREATE_WORKSPACES);
    }
    member.roles = roles;
  }

  /**
   * Update members selected status
   */
  updateSelectedStatus(): void {
    this.membersSelectedNumber = 0;
    this.isBulkChecked = !!this.members.length;
    this.members.forEach((member: any) => {
      if (this.membersSelectedStatus[member.email]) {
        this.membersSelectedNumber++;
      } else {
        this.isBulkChecked = false;
      }
    });
  }

  /**
   * Change bulk selection value.
   */
  changeBulkSelection(): void {
    if (this.isBulkChecked) {
      this.deselectAllMembers();
      this.isBulkChecked = false;
      return;
    }
    this.selectAllMembers();
    this.isBulkChecked = true;
  }

  /**
   * Check all members in list.
   */
  selectAllMembers(): void {
    this.membersSelectedNumber = this.members.length;
    this.members.forEach((member: any) => {
      this.membersSelectedStatus[member.email] = true;
    });
  }

  /**
   * Uncheck all members in list
   */
  deselectAllMembers(): void {
    this.membersSelectedStatus = {};
    this.membersSelectedNumber = 0;
  }

  /**
   * Adds member to the list.
   *
   * @param user
   * @param roles
   */
  addMember(user: any, roles: Array<any>): void {
    user.roles = roles;
    this.members.push(user);
    this.buildMembersList();
  }

  /**
   * Shows dialog to add new member.
   *
   * @param $event
   */
  showAddDialog($event: MouseEvent): void {
    this.$mdDialog.show({
      targetEvent: $event,
      controller: 'AddMemberController',
      controllerAs: 'addMemberController',
      bindToController: true,
      clickOutsideToClose: true,
      locals: {
        members: this.members,
        callbackController: this
      },
      templateUrl: 'app/teams/invite-members/add-member/add-member.html'
    });
  }

  /**
   * Removes selected members.
   */
  removeSelectedMembers(): void {
    this.lodash.remove(this.members, (member: any) => {
      return this.membersSelectedStatus[member.email];
    });
    this.buildMembersList();
    this.deselectAllMembers();
    this.isBulkChecked = false;
  }
}
