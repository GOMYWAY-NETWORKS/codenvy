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
 * Controller for team member item..
 *
 * @author Ann Shumilova
 */
export class MemberItemController {
  /**
   * Service for displaying dialogs.
   */
  private $mdDialog: angular.material.IDialogService;
  /**
   * Controller for handling callback events. (Comes from directive's scope).
   */
  private callback: any;
  /**
   * Member to be displayed. (Comes from directive's scope).
   */
  private member: any;

  /**
   * Default constructor that is using resource injection
   * @ngInject for Dependency injection
   */
  constructor($mdDialog: angular.material.IDialogService) {
    this.$mdDialog = $mdDialog;
  }

  /**
   * Call user permissions removal. Show the dialog
   * @param  event - the $event
   */
  removeMember(event: MouseEvent): void {
    let confirm = this.$mdDialog.confirm()
      .title('Would you like to remove member  ' + this.member.email + ' ?')
      .content('Please confirm for the member removal.')
      .ariaLabel('Remove member')
      .ok('Remove')
      .cancel('Cancel')
      .clickOutsideToClose(true)
      .targetEvent(event);
    this.$mdDialog.show(confirm).then(() => {
      this.callback.removePermissions(this.member);
    });
  }

  /**
   * Returns string with member actions.
   *
   * @returns {string} string format of actions array
   */
  getMemberActions(): void {
    return this.member.permissions.actions.join(', ');
  }
}

