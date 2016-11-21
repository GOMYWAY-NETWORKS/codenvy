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
 * Defines a directive for checking whether team name already exists.
 *
 * @author Ann Shumilova
 */
export class UniqueTeamNameValidator {

  /**
   * Default constructor that is using resource
   * @ngInject for Dependency injection
   */
  constructor (codenvyTeam, $q) {
    this.codenvyTeam = codenvyTeam;
    this.$q = $q;
    this.restrict='A';
    this.require = 'ngModel';
  }

  /**
   * Check that the name of team is unique
   */
  link($scope, element, attributes, ngModel) {

    // validate only input element
    if ('input' === element[0].localName) {

      ngModel.$asyncValidators.uniqueTeamName = (modelValue) => {

        // parent scope ?
        var scopingTest = $scope.$parent;
        if (!scopingTest) {
          scopingTest = $scope;
        }

        let currentTeamName = scopingTest.$eval(attributes.uniqueTeamName),
          teams = this.codenvyTeam.getTeams();
        if (teams.length) {
          for (let i = 0; i < teams.length; i++) {
            if (teams[i].name === currentTeamName) {
              continue;
            }
            if (teams[i].name === modelValue) {
              return this.$q.reject(false);
            }
          }
          return this.$q.resolve(true);
        } else {
          return this.$q.resolve(true);
        }
      };
    }
  }
}
