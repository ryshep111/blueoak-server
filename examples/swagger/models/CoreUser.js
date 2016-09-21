var _ = require('lodash'),
    authorization = require('express-authorization');

/**
 * CoreUser is the base model that describes a user in the ESB.
 *
 * @param  {Object} userData properties describing the core user.
 * Sample userData used to hydrate a new CoreUser.
 *
 * {
 * 	"userid": "roger.dodger@gmail.com",
 * 	"username": "Roger P. Dodger",
 * 	"permissions": ["api:*:*"],
 * 	"enabled": true,
 * 	"realm": "app_authentication",
 * 	"mappedUsers" : {
 * 		"data-provider": {
 * 			"name": "data-provider-id"
 * 		}
 * 	}
 * }
 */

var CoreUser = function (userData) {
    var _userData = _.clone(userData, true);
    Object.defineProperties(this, {
        // user's unique identifier (email, api-id)
        userid : {
            value: _.get(_userData, 'userid'),
            enumerable: true
        },
        // user's displayable name (Roger P. Dodger, PointSource, anonymous)
        username: {
            value: _.get(_userData, 'username'),
            enumerable: true
        },
        // user's list of assigned permissions
        permissions: {
            value: _.get(_userData, 'permissions', []),
            enumerable: true
        },
        // Is user enabled (false should restrict the user for accessing any api's)
        // Overrides any permissions and disables the users access when false
        enabled:  {
            value: _.get(_userData, 'enabled', false),
            enumerable: true
        },

        // Authentication realm in which the user was authenticated
        realm: {
            value: _.get(_userData, 'realm', null),
            enumerable: true,
            writable: true
        },
        /**
         * A  collection of credentials this user can act as when interacting with external services
         * (esb service bindings)
         * The intended use of this collection is to allow the User to map his ESB authenticated account to one or more
         * supporting service accounts.  For example an IQ user needs to act as an agent when interacting with the
         * policyport services.
         *
         * {
         * 	"binding" : {binding specific authentication properties},
         * 	"policyport" : {"name": "PSIQSFIAPI"},
         * 	"sample-service" :{ apiId: "abc1234", "apiSecret" :"itsasecret"}
         * }
         *
         * @type {Object}
         */
        userMap: {
            value: _.get(_userData, 'mappedUsers', {}),
            enumerable: true
        }
    });
};

_.extend(CoreUser.prototype, {
    inspects: function () {
        return {
            userid: this.userid,
            username: this.username,
            permissions: this.permissions,
            enabled: this.enabled,
            realm: this.realm,
            userMap: this.userMap
        };
    },
    getUserName: function () {
        return this.username;
    },
    getUserId: function () {
        return this.userid;
    },
    getUniqueId: function () {
        return this.userid;
    },
    getPermissions: function () {
        return this.permissions;
    },
    addPermission: function (perm) {
        this.permissions.push(perm);
    },
    isPermitted : function (perms) {
        return authorization
            .considerPermissions(this.permissions)
            .isPermitted(perms);
    },
    isEnabled : function () {
        return this.enabled;
    },
    getUserMapping: function (mappedUser) {
        var mappedUsers = this.userMap || {};
        return mappedUsers[mappedUser];
    },
    /* deprecated methods */
    getName : function () {
        console.warn ('deprecated function call to CoreUser.getName()');
        return this.username;
    },
    isAnonymous : function () {
        console.warn ('deprecated function call to CoreUser.isAnonymous()');
        return (this.userid === 'anonymous');
    },
    setPermissions : function (perms) {
        console.warn ('deprecated function call to CoreUser.setPermissions()');
        this.permissions = perms;
    },
    toString: function () {
        console.warn ('deprecated function call to CoreUser.toString()');
        return this.username + this.userid;
    },
    toDebugString: function () {
        console.warn ('deprecated function call to CoreUser.toDebugString()');
        return JSON.stringify(this, null, 2);
    },
    serialize: function () {
        return {
            username: this.username,
            userid: this.userid,
            permissions: this.permissions,
            enabled: this.enabled,
            realm: this.realm,
            mappedUsers: this.userMap
        };
    }
});

/* Public Api */
module.exports = CoreUser;

