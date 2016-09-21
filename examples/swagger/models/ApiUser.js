var _ = require('lodash'),
    util = require('util'),
    CoreUser = require('./CoreUser');

/**
 * ApiUser describes a user that is stored in the apikey cloudant/couch database.
 * Typically, this user will be used to define 3rd party system api users accessing
 * system via an HMAC signed request.
 *
 * @param {Object} apiData properties describing the api user.
 *
 * Sample userData used to hydrate a new ApiUser.
 * {
 * 	"authentication" : {
 * 		"apiId": "7e06c4a6-61bc-45a8-b2d7-24c405e8b27c",
 *   	"apiKey": "rqwHvMvGLgtKNrgOpksK6rlIdyqZtD1mKVAsFzKJTOg",
 *    	"enabled": true
 * 	}
 * 	"name": "Frank Krank Service's, LLC",
 * 	"permissions": ["api:*:*"],
 * 	"mappedUsers" : {
 * 		"data-provider": {
 * 			"name": "data-provider-id"
 * 		}
 * 	}
 * }
 */
var ApiUser = function (apiData) {
    var userData = {
        userid:  _.get(apiData, 'authentication.apiId'),
        username:  _.get(apiData, 'name'),
        permissions: _.get(apiData, 'permissions'),
        enabled: _.get(apiData, 'authentication.enabled'),
        mappedUsers: _.get(apiData, 'mappedUsers'),
        realm: _.get(apiData, 'realm')
    };
    ApiUser.super_.call(this, userData);

    // API message signing key
    Object.defineProperty(this, 'signerKey', {
        value: _.get(apiData, 'authentication.apiKey')
    });
};

util.inherits(ApiUser, CoreUser);

_.extend(ApiUser.prototype, {
    getApiId : function () {
        console.warn ('deprecated function call to ApiUser.getApiId(). Use ApiUser.getUserId().');
        return ApiUser.super_.prototype.getUserId.call(this);
    },
    getApiKey : function () {
        return this.signerKey;
    }
});

/* Public Api */
module.exports = ApiUser;

