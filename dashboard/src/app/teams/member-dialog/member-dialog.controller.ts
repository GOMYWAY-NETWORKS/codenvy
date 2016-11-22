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
import {CodenvyUser} from '../../../components/api/codenvy-user.factory';
import {CodenvyTeam} from '../../../components/api/codenvy-team.factory';
import {CodenvyTeamRoles} from '../../../components/api/codenvy-team-roles';

/**
 * @ngdoc controller
 * @name teams.member:MemberDialogController
 * @description This class is handling the controller for adding/editing members dialog.
 * @author Ann Shumilova
 */
export class MemberDialogController {
  /**
   * Team API interaction.
   */
  private codenvyTeam: CodenvyTeam;
  /**
   * User API interaction.
   */
  private codenvyUser: CodenvyUser;
  /**
   * Service for displaying dialogs.
   */
  private $mdDialog: angular.material.IDialogService;
  /**
   * Processing state of adding member.
   */
  private isProcessing: boolean;
  /**
   * Set of user roles info.
   */
  private roles: Array<any>;
  /**
   * Already added emails.
   */
  private emails: Array<string>;
  /**
   * Existing members.
   */
  private members: Array<any>;
  /**
   * Entered email address.
   */
  private email: string;
  /**
   * Controller that will handle callbacks.
   */
  private callbackController: any;

  /**
   * Member to be displayed, may be <code>null</code> if add new member is needed. (Comes from )
   */
  private member: any;
  /**
   * Dialog window title.
   */
  private title: string;
  /**
   *
   */
  private buttonTitle: string;
  /**
   * Default constructor that is using resource
   * @ngInject for Dependency injection
   */
  constructor($mdDialog: angular.material.IDialogService, codenvyTeam: CodenvyTeam, codenvyUser: CodenvyUser) {
    this.$mdDialog = $mdDialog;
    this.codenvyTeam = codenvyTeam;
    this.codenvyUser = codenvyUser;

    this.isProcessing = false;
    this.roles = [];
    if (this.member) {
      this.title = 'Edit ' + this.member.name + ' roles';
      this.buttonTitle = 'Save';
      this.email = this.member.email;
      let roles = this.codenvyTeam.getRolesFromActions(this.member.permissions.actions);
      this.roles.push({'role' : CodenvyTeamRoles.MANAGE_WORKSPACES, 'allowed' : roles.indexOf(CodenvyTeamRoles.MANAGE_WORKSPACES) >= 0});
      this.roles.push({'role' : CodenvyTeamRoles.MANAGE_TEAM, 'allowed' : roles.indexOf(CodenvyTeamRoles.MANAGE_TEAM) >= 0});
      this.roles.push({'role' : CodenvyTeamRoles.CREATE_WORKSPACES, 'allowed' : roles.indexOf(CodenvyTeamRoles.CREATE_WORKSPACES) >= 0});
      this.roles.push({'role' : CodenvyTeamRoles.MANAGE_RESOURCES, 'allowed' : roles.indexOf(CodenvyTeamRoles.MANAGE_RESOURCES) >= 0});
    } else {
      this.email = '';
      this.title = 'Invite user to collaborate';
      this.buttonTitle = 'Add';
      this.roles.push({'role' : CodenvyTeamRoles.MANAGE_WORKSPACES, 'allowed' : true});
      this.roles.push({'role' : CodenvyTeamRoles.MANAGE_TEAM, 'allowed' : false});
      this.roles.push({'role' : CodenvyTeamRoles.CREATE_WORKSPACES, 'allowed' : true});
      this.roles.push({'role' : CodenvyTeamRoles.MANAGE_RESOURCES, 'allowed' : false});
    }
    this.emails = [];
    this.members.forEach((member: any) => {
      this.emails.push(member.email);
    });
  }

  /**
   * Hides the add member dialog.
   */
  hide(): void {
    this.$mdDialog.hide();
  }

  /**
   * Checks whether enter email is unique.
   *
   * @param email email to check
   * @returns {boolean} true if pointed email dis not in list yet
   */
  isUnique(email: string): boolean {
    return this.emails.indexOf(email) < 0;
  }

  /**
   * Adds new member.
   */
  addMember(): void {
    let userRoles = this.getRoles();

    let user = this.codenvyUser.getUserByAlias(this.email);
    if (user) {
      this.finishAdding(user, userRoles);
      return;
    }

    user = {};
    user.email = this.email;
    this.isProcessing = true;

    this.codenvyUser.fetchUserByAlias(this.email).then(() => {
      user = this.codenvyUser.getUserByAlias(this.email);
      this.finishAdding(user, userRoles);
    }, (error: any) => {
      this.finishAdding(user, userRoles);
    });
  }

  /**
   * Forms the list of user's roles by role's info from page.
   *
   * @returns {Array<any>} roles
   */
  getRoles(): Array<any> {
    let userRoles = [];
    this.roles.forEach((roleInfo: any) => {
      if (roleInfo.allowed) {
        userRoles.push(roleInfo.role);
      }
    });
    return userRoles;
  }

  /**
   * Handle edit member user's action.
   */
  editMember(): void {
    let userRoles = this.getRoles();
    this.member.permissions.actions = this.codenvyTeam.getActionsFromRoles(userRoles);
    this.callbackController.updateMember(this.member);
    this.hide();
  }

  /**
   * Finish adding user state.
   *
   * @param user user to be added
   * @param roles user's roles
   */
  finishAdding(user: any, roles: any): void {
    this.isProcessing = false;
    this.callbackController.addMember(user, roles);
    this.hide();
  }

}
