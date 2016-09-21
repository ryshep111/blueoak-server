var _ = require('lodash'),
    util = require('util'),
    uuid = require('node-uuid'),
    ApiUser = require('./ApiUser');

/**
 * WebSessionUser describes a user that is stored in the apikey cloudant/couch database.
 * Typically, this user will be used for users accessing anonymously to the ESB.
 * The user enables support for persisting dynamic (runtime) permissions via cookie session.
 *
 * @param {Object} apiData properties describing the api user.
 *
 * Sample userData used to hydrate a new ApiUser.
 * {
 * 	"authentication" : {
 * 		"apiId": "anonymous",
 *    	"enabled": true
 * 	}
 * 	"name": "anonymous",
 * 	"permissions": ["api:*:*"],
 * 	"mappedUsers" : {
 * 		"data-provider": {
 * 			"name": "data-provider-id"
 * 		}
 * 	}
 * }
 *
 * @param  {Session object} session The users session data associated with the incoming request.
 */
var WebSessionUser = function (userData, session) {
    var self = this;
    WebSessionUser.super_.call(self, userData);

    // The request is used to support the mgmt. of the cookie containing the
    // imputed permissions allowed during then user's session.
    Object.defineProperty(this, 'session', {value: session});

    //Restore any permissions from the web user's session
    var userSession = _.get(session, 'user');
    if (userSession && userSession.p && _.isArray(userSession.p)) {
        userSession.p.forEach(function (perm) {
            WebSessionUser.super_.prototype.addPermission.call(self, perm);
        });
    }
};

util.inherits(WebSessionUser, ApiUser);

_.extend(WebSessionUser.prototype, {
    addPermission: function (perm) {
        WebSessionUser.super_.prototype.addPermission.call(this, perm);
        // custom logic for persisting permissions to a session token
        var userSession = _.get(this.session, 'user');
        if (!userSession) {
            userSession = {
                p: []
            };
        }
        userSession.p.push(perm);
        _.set(this.session, 'user', userSession);
    },
    getUniqueId: function () {
        if (_.isUndefined(this.session.correlator)) {
            _.set(this, 'session.correlator', uuid.v4());
        }

        return this.session.correlator;
    }
});

/* Public Api */
module.exports = WebSessionUser;

