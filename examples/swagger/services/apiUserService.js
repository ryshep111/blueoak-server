var q = require('q'),
    _ = require('lodash'),
    /******************* User Models ***************/
    CoreUser = require('../models/CoreUser'),
    ApiUser = require('../models/ApiUser'),
    WebSessionUser = require('../models/WebSessionUser'),
    log, couch, Cache;

/**
 * UserIdLookupTable is a collection of the User's _id values that have
 * been retrieved. The _id's are keyed by the name or apiId used to lookup
 * the ApiUser(_id).
 * 	[ {
 * 		name: apiId|name,
 * 		id: _id
 * 	} ]
 *
 * @type {Array}
 */
var UserIdLookupTable = [];
var CACHE_NS = 'ApiUserNs';
var USER_TTL = 600; // cache instance time to live (seconds == 10 minutes)

/* private methods */
function _retrieveFromCache(id) {
    return q.nfcall(Cache.nsGet, CACHE_NS, id);
}

function _addToCache(name, id, user) {
    return q.nfcall(Cache.nsSet, CACHE_NS, id, user, USER_TTL)
        .then(function () {
            UserIdLookupTable.push ({name: name, id: id});
            return user;
        });
}

/**
 * Retrieve's the API User
 * @param  {[type]} key  Key used to lookup the ApiUser from the database.
 * @param  {[type]} view Database view to use to query the ApiUser from the database
 * @return {[type]}      Returns the ApiUser or undefined (if user was found)
 */
function _retrieveFromDb(key, view) {
    var db = couch.get('apikey');
    if (!db) {
        log.error('apikey database not available');
        return q.Promise(function (resolve) {
            resolve(undefined);
        });
    }

    return q.nfcall(db.view, 'apikey', view, { key: key })
        .then(function (doc) {
            if (doc[0] && doc[0].rows.length <= 0) {
                return undefined;
            }
            var userData = doc[0].rows[0].value;
            return _addToCache(key, userData._id, userData);
        });
}


function _flushApiUserById(id) {
    return q.nfcall(Cache.nsDel, CACHE_NS, id)
        .then(function () {
            _.remove(UserIdLookupTable, function (n) {
                return (n.id === id);
            });
        }).catch(function (err) {
            log.warn('Error encountered while flush api user from the cache', err);
        });
}

function _retrieveFromDbByName(name) {
    return _retrieveFromDb(name, 'AllApiUsersByName');
}

function _retrieveFromDbByApiId(apiId) {
    return _retrieveFromDb(apiId, 'AllApiUsersById');
}

/**
 * Service Methods
 */

function init(logger, bosCouchdb, localCache) {
    log = logger;
    couch = bosCouchdb;
    Cache  = localCache;

    //set up apiKey database monitoring
    var db = couch.get('apikey');
    // monitor changes to the couch db
    var changesFeed = db.follow({since: 'now'});
    changesFeed.on('start', function () {
        changesFeed.on('change', function (change) {
            _flushApiUserById(change.id);
        });
    });
    changesFeed.follow();
    log.info('ApiUserService initialized');
}

/* General API User Methods */

/**
 * Retrieves the ApiUser record from the database. The ApiUser record will be cached for the period of the @USER_TTL.
 * @param  {String}       name The name of the ApiUser.
 * @return {ApiUserModel}      ApiUser or undefined
 */
function getUserByName(name) {
    var idEntry = _.find(UserIdLookupTable, {name: name});
    if (idEntry) {
        // cache hit expected
        return _retrieveFromCache(idEntry.id)
            .then(function (userEntry) {
                if (!userEntry) {
                    return _retrieveFromDbByName(name);
                }
                return userEntry;
            });
    }
    return _retrieveFromDbByName(name);
}
/**
 * Retrieves the ApiUser record from the database. The ApiUser record will be cached for the period of the @USER_TTL.
 * @param  {[type]}         apiId The authentication.apiId of the ApiUser.
 * @return {ApiUserModel}         ApiUser or undefined
 */
function getUserByApiId(apiId) {
    var idEntry = _.find(UserIdLookupTable, {name: apiId});
    if (idEntry) {
        // cache hit expected
        return _retrieveFromCache(idEntry.id)
            .then(function (user) {
                if (!user) {
                    return _retrieveFromDbByApiId(apiId);
                }
                return user;
            });
    }
    return _retrieveFromDbByApiId(apiId);
}

/* Authentication-workflow Methods */
/**
 * A pluggable method for verifying and reconsituting the ApiUser based on name.  This method
 * can be used by the x-securityDefinition registration facillites available via the authentication middleware.
 *
 * Typical use is for the anonymous strategy registration.
 *
 * @param  {[type]}   name     The name of the user verify and reconsitute.
 * @param  {[type]}   req      The request object.
 * @param  {Function} callback The verify callback provided by passport.js authentication strategy.
 * @return {[type]}            A reconsituted WebSessionUser (if the user is found), false if not found.
 */
function getWebUserByName(req, name, callback) {
    if (!_.isFunction(callback)) {
        callback = name;
        name = req;
        req = undefined;
    }
    getUserByName(name).then(function (userData) {
        if (!userData) {
            return callback(null, false);
        }
        callback(null, new WebSessionUser(userData, _.get(req, 'session')));
    }).catch(function (error) {
        log.warn('Error encountered searching for web user', name, error);
        return callback(new Error('Error encountered searching for web user ' + name));
    });
}

/**
 * A pluggable method for verifying and reconsituting the ApiUser based on apiId.  This method
 * can be used by the x-securityDefinition registration facillites available via the authentication middleware.
 *
 * Typical use is for the hmac strategy registration.
 *
 * @param  {[type]}   apiId    The apiId of the user.
 * @param  {Function} callback The verify callback provided by passport.js authentication strategy.
 * @return {[type]}             A reconsituted ApiUser (if the user is found), false if not found.
 */
function getApiUserById(apiId, callback) {
    getUserByApiId(apiId).then(function (userData) {
        if (!userData) {
            return callback(null, false);
        }
        return callback(null, new ApiUser(userData));
    }).catch(function (error) {
        log.warn('Error encountered searching for api user', apiId, error);
        return callback(new Error('Error encountered searching for api user ' + apiId));
    });
}

/* Public API */
module.exports = {
    init: init,
    getUserByApiId: getUserByApiId,
    getUserByName: getUserByName,
    getWebUserByName: getWebUserByName,
    getApiUserById: getApiUserById,
    models: {
        ApiUser: ApiUser,
        CoreUser: CoreUser,
        WebSessionUser: WebSessionUser
    }
};

