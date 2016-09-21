var __ = require('lodash');

var log;
var esbCache;
var DEFAULT_NAMESPACE = '$def$';

function init(logger, cache) {
    log = logger;
    esbCache = cache;
}

function makeKey(namespace, key) {
    return (namespace ? namespace : DEFAULT_NAMESPACE) + '_' + key;
}

function nsGet(namespace, key, callback) {
    return esbCache.get(makeKey(namespace, key), callback);
}

function get(key, callback) {
    return nsGet(DEFAULT_NAMESPACE, key, callback);
}

function nsSet(namespace, key, value, ttl, callback) {
    if (__.isFunction(ttl)) {
        callback = ttl;
        ttl = undefined;
    }
    return esbCache.set(makeKey(namespace, key), value, ttl, callback);
}

function set(key, value, ttl, callback) {
    return nsSet(DEFAULT_NAMESPACE, key, value, ttl, callback);
}

function nsDel(namespace, key, callback) {
    var keys;
    if (__.isArray(key)) {
        keys = __.map(key, function (k) {
            return makeKey(namespace, k);
        });
        return esbCache.getClient().del(keys, callback);
    }
    return esbCache.getClient().del(makeKey(namespace, key), callback);
}

function del(key, callback) {
    return nsDel(DEFAULT_NAMESPACE, key, callback);
}

module.exports = {
    init: init,
    set: set,
    nsSet: nsSet,
    get: get,
    nsGet: nsGet,
    del: del,
    nsDel: nsDel
};

