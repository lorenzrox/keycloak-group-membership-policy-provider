'use strict';

var module = angular.module('keycloak');

module.requires.push('ui.ace');

module.config(['$routeProvider', function ($routeProvider) {
    $routeProvider
        .when('/realms/:realm/clients/:client/authz/resource-server/policy/group-membership/create', {
            templateUrl: resourceUrl + '/partials/authz/policy/provider/resource-server-policy-group-membership-detail.html',
            resolve: {
                realm: function (RealmLoader) {
                    return RealmLoader();
                },
                client: function (ClientLoader) {
                    return ClientLoader();
                }
            },
            controller: 'ResourceServerPolicyGroupMembershipDetailCtrl'
        }).when('/realms/:realm/clients/:client/authz/resource-server/policy/group-membership/:id', {
            templateUrl: resourceUrl + '/partials/authz/policy/provider/resource-server-policy-group-membership-detail.html',
            resolve: {
                realm: function (RealmLoader) {
                    return RealmLoader();
                },
                client: function (ClientLoader) {
                    return ClientLoader();
                }
            },
            controller: 'ResourceServerPolicyGroupMembershipDetailCtrl'
        });
});

module.controller('ResourceServerPolicyGroupMembershipDetailCtrl', function ($scope, $route, $location, realm, PolicyController, client, serverInfo) {
    PolicyController.onInit({
        getPolicyType: function () {
            return "group-membership";
        },

        onInit: function () {
        },

        onInitUpdate: function (policy) {
        },

        onUpdate: function () {
            delete $scope.policy.config;
        },

        onInitCreate: function (newPolicy) {
        },

        onCreate: function () {
            delete $scope.policy.config;
        }
    }, realm, client, $scope);
});