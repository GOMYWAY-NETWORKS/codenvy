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
import {CodenvyUser} from '../../../../components/api/codenvy-user.factory';
import {CodenvyTeam} from '../../../../components/api/codenvy-team.factory';
import {CodenvyTeamRoles} from '../../../../components/api/codenvy-team-roles';

/**
 * @ngdoc controller
 * @name teams.invite.members:AddMemberController
 * @description This class is handling the controller for adding members dialog.
 * @author Ann Shumilova
 */
export class AddMemberController {
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
   * Default constructor that is using resource
   * @ngInject for Dependency injection
   */
  constructor($mdDialog: angular.material.IDialogService, codenvyTeam: CodenvyTeam, codenvyUser: CodenvyUser) {
    this.$mdDialog = $mdDialog;
    this.codenvyTeam = codenvyTeam;
    this.codenvyUser = codenvyUser;

    this.isProcessing = false;

    this.roles = [];
    this.roles.push({'role' : CodenvyTeamRoles.MANAGE_WORKSPACES, 'allowed' : true});
    this.roles.push({'role' : CodenvyTeamRoles.MANAGE_TEAM, 'allowed' : false});
    this.roles.push({'role' : CodenvyTeamRoles.CREATE_WORKSPACES, 'allowed' : true});
    this.roles.push({'role' : CodenvyTeamRoles.MANAGE_RESOURCES, 'allowed' : false});

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
    let userRoles = [];
    this.roles.forEach((roleInfo: any) => {
      if (roleInfo.allowed) {
        userRoles.push(roleInfo.role);
      }
    });

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
