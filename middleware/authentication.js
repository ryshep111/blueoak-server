var _ = require('lodash'),
    passport = require('passport'),
    authorization = require('express-authorization'),
    HmacStrategy = require('passport-hmac-strategy').Strategy
var log, cfg;

var httpMethods = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch'];

// Available strategies
var SupportedStrategies = {
    hmac : HmacStrategy
};

// Collection of registered security definitions
var registered = [];

/**
 * Authentication services providing authentication and authorization services.
 *
 * Implements a extension model based on the Swagger security definitions and security
 * requirements specification elements.
 *
 * 'x-securityDefintions' : Is an extension of the Swagger object's Security Definitions Object.
 *
 *      name : name of the security definition. Is referenced by the x-security requirement.
 *      type : type of security strategy. Currently support types include:
 *          jwt : provides authentication based on an JSON Web Token provided as a
 *                  part of the request.  Based on passport-jwt strategy.
 *          token : provides authentication based on an accesstoken provided as a
 *                  part of the request.  Based on passport-accesstoken strategy.
 *          hmac : provides authentication based on an HMAC signature provided as a
 *                  part of the request.  Implemented via custom strategy -
 *                  passport-hmac-strategy
 *          anon : provides anonymous authentication.  Implemented via custom strategy -
 *                  passport-anonymous-strategy
 *
 *      "name": {
 *          "type" : "[token|hmac|anon]",
 *          "description" : "description",
 *          "method" :  "service.verify"
 *      }
 *
 * 'x-security' :  Is an extension of the Swagger object's Security Requirements Object.
 *
 * Core user model provided via authentication services:
 * {
 *      userid : "ID of the authenticated user",
 *      username: "Displayable name of the user",
 *      permissions :["shiro like permission ('api:quote:read')"]
 * }
 *
 * The user returned by a verification method, can contain additional properties.
 *
 * @param  {[type]} app    [description]
 * @param  {[type]} logger [description]
 * @return {[type]}        [description]
 */
function init(app, config, logger, serviceLoader, swagger) {
    log = logger;
    cfg = config.get('authentication');
    app.use(passport.initialize());

    _.forEach(swagger.getSimpleSpecs(), function (api, name) {
        log.debug('installing security for API ' + name);
        var basePath = api.basePath || '';

        // wire in security definitions
        if (api['x-securityDefinitions']) {
            // wire in the authentication strategies
            var strategies = api['x-securityDefinitions'];
            _.keys(api['x-securityDefinitions']).forEach(function (strategyId) {
                if (_.find(registered, _.matches({ name: strategyId }))) {
                    return logger.debug('Security Definition is already registered for %s. skipping...', strategyId);
                }
                var definition = strategies[strategyId];
                if (definition.method && _.isString(definition.method)) {
                    var parts = definition.method.split('.');
                    var verificationSvc = serviceLoader.get(parts[0]);
                    if (!verificationSvc) {
                        return logger.warn('Could not find service module named "%s".', parts[0]);
                    }
                    if (!verificationSvc[parts[1]] && !_.isFunction(verificationSvc[parts[1]])) {
                        return logger.warn('Verification function %s on module %s is missing or invalid.',
                            parts[1], parts[0]);
                    }
                    _register(strategyId, definition.type, verificationSvc[parts[1]], definition.options);
                }
            });
        }

        /* apply security requirements to each route path*/
        _.keys(api.paths).forEach(function (path) {
            var pathObj = api.paths[path];
            var routePath = basePath + _convertPathToExpress(path);

            //loop for http method keys, like get an post
            _.keys(pathObj).forEach(function (method) {
                if (_.contains(httpMethods, method)) {
                    var operation = pathObj[method];
                    if (operation['x-security']) {
                        _applySecurityRequirement(app, method, routePath, operation['x-security']);
                    }
                }
            });
        });
    });
}

/**
 * Register a new instance of an authentication strategy.
 * @param  {String} strategyId Identifer used to reference the strategy.
 * @param  {String} type       Type of authentication strategy
 * @param  {Function} verifyFn Verification method used to look up the user record.
 * @param  {Object} opts       Strategy configuration options
 */
function _register(strategyId, type, verifyFn, opts) {
    log.debug ('Registering security definition type %s, with name %s', type, strategyId);
    if (!_.has(SupportedStrategies, type)) {
        return log.warn('Security definition type "%s" is not supported.', type);
    }

    // Populate any options that indicate they need to be retrieved from config
    var re = /^{{(.*)}}$/;
    _.each(opts, function (value, key) {
        var result = re.exec(value);
        if (result && result[1]) {
            // This is a config-based option
            opts[key] = _.get(cfg, result[1]);
        }
    });

    var wrappedVerifyFn = _wrapVerify(strategyId, verifyFn);
    var strategy = new SupportedStrategies[type]((opts) ? opts : {}, wrappedVerifyFn);
    passport.use(strategyId, strategy);
    registered.push({
        name: strategyId,
        type: type,
        method: wrappedVerifyFn,
        options : opts
    });
}

/**
 * middleware authentication method
 * @param  {String|Array} strategyIds  Either the id of the strategy to authenticate against.
 *                                     Can also be an array of strategy ids.
 * @param  {Object} options     authentication configuration options
 * @return {Function}             express middleware handler
 */
function _authenticate(strategyIds, options) {
    return passport.authenticate(strategyIds, options);
}

function _applySecurityRequirement(app, method, route, securityReq) {
    var strategies = _.keys(securityReq);

    // attach the security authentication schema(s) middleware to the route.
    if (!_.isEmpty(strategies)) {

        log.debug('Applying security requirements %s to route %s %s',
            strategies.toString(), method, route);
        app[method].call(app, route, _authenticate(strategies, {session: false}));
    }

    // attach the authorization middleware to the route.
    log.debug('Restricting route %s %s for realms %s.', method, route, strategies.toString());
    app[method].call(app, route, _.partial(_validatePermissions, securityReq, route));
}

function _validatePermissions(securityReq, route, req, res, next) {
    var realm  = _.get(req, 'user.realm');
    if (_.isEmpty(securityReq[realm])) {
        // no permission - nothing to see here.  move on!
        next();
        return;
    }
    // TODO: Add logging around permission denial
    var userPerms = (req.user && _.isFunction(req.user.getPermissions)) ?
        req.user.getPermissions() : [];

    var subject = authorization.considerPermissions(userPerms);
    var requiredPerms = _expandRouteInstancePermissions(securityReq[realm], route, req.path);

    var isPermitted = subject.isPermitted(requiredPerms);
    if (!isPermitted) {
        res.status(403).send();
        return;
    }
    next();
}

/**
 * Expands a set of permissions ( e.g. ones registered with the x-security instance) to be route instance
 * specific.  A route secured with a permission, which includes a reference to a route path parameter
 * (e.g. - 'resource:read:{id}'), should be validated at runtime using the specified path value.
 * This method uses the registered route and the specific request url to replace the templated path parameter
 * with the specific request instance id.
 *
 * For example, if the route GET /resouce/:id was secured with the permission set of ['resource:read:{id}'], and
 * the route accessed via GET /resource/2.  The permission array returned would be ['resource:read:2'], so that
 * the permission check (isPermitted) would confirm the user has access to this specific instance of the resource.
 *
 * @param  {Array}  perms Array of permission entries - ['api:read:test-api','resource:read:{pathid}']
 * @param  {String} route Registered route (e.g - /resouce/:id)
 * @param  {String} uri   Runtime instance uri instance of the route (e.g. - /resouce/2)
 * @return {Array}        An array of permissions with the route path parameters substituted
 */
function _expandRouteInstancePermissions(perms, route, uri) {
    /* relate the route path parameters to the url instance values
     perms: ["api:read:{policyid}", "api:read:{claimid}"]
     route: /api/v1/policies/:policyid/claims/:claimid
     [ api,v1,policies,:policyid,claims,:claimid ]
     uri:   /api/v1/policies/SFIH1234534/claims/37103
     [ api,v1,policies,SFIH1234534,claims,37103 ]
     */
    if (!_.isString(route) ||  !_.isString(uri)) {
        return perms;
    }
    var routeParts = route.split('/');
    var uriParts = uri.split('/');

    // [ [ ':policyid', 'SFIH1234534' ], [ ':claimid', '37103' ] ]
    var pathIds = _.zip(routeParts, uriParts)
        .filter(function (b) {
            return _.startsWith(b[0], ':');
        }).map(function (path) {
            // trim the :
            path[0] = path[0].substr(1);
            return path;
        });

    return _.map(perms, function (perm) {
        var ePerm = perm;
        _.forEach(pathIds, function (item) {
            ePerm = ePerm.replace('{' + item[0] + '}', item[1]);
        });
        return ePerm;
    });
}


//swagger paths use {blah} while express uses :blah
function _convertPathToExpress(swaggerPath) {
    var reg = /\{([^\}]+)\}/g;  //match all {...}
    swaggerPath = swaggerPath.replace(reg, ':$1');
    return swaggerPath;
}

/**
 * verification callback wrapper to allow assignment of the which strategy
 * successfully authenticated the request
 * @param  {String} strategyId Id of the strategy associated with the verify callback.
 * @param  {Function} verify     Verify callback used by passport.
 * @return {Function}            Function wrapping the verify callback.
 */
function _wrapVerify(strategyId, verify) {
    return function () {
        var args = new Array(arguments.length);
        for (var i = 0; i < args.length; ++i) {
            args[i] = arguments[i];
        }
        var done = args.pop();
        args.push (function (err,user,info) {
            if (!err && user) {
                user.realm = strategyId;
            }
            done (err, user, info);
        });
        verify.apply(this, args);
    };
}

/* Public API */
module.exports = {
    init : init
};

