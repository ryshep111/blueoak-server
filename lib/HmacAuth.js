var urlParse,
    myHmac,
    sjcl,
    path;

var HmacAuthorization = function (name, id, key) {
    this.name = name;
    if (myHmac) {
        id = myHmac.id;
        key = myHmac.key;
    }
    this.id = id;
    this.key = key;
};

HmacAuthorization.prototype.apply = function (obj, authorizations) {
    var contentMd5 = obj.headers['Content-MD5'] || '';
    var contentType = obj.headers['Content-Type'] || '';
    var dateString = new Date().toString();

    var urlPath = urlParse(obj.url).pathname;
    var stringToSign = obj.method.toUpperCase() + '\n' +
        contentMd5 + '\n' +
        contentType + '\n' +
        dateString + '\n' +
        urlPath;

    var key = sjcl.codec.utf8String.toBits(this.key);
    var out = (new sjcl.misc.hmac(key, sjcl.hash.sha256)).mac(stringToSign);
    var hmac = sjcl.codec.base64.fromBits(out);
    obj.headers.Authorization = 'SFI ' + this.id + ':' + hmac + ':' + dateString;
    console.log('Authorization: ' + obj.headers.Authorization);
};

// "browserify" to work with both Swagger-UI and Swagger Commander
(function (name, definition) {
    sjcl = require('./sjcl');
    urlParse = require('url-parse');
    path = require('path');
    try {
        var fs = require('fs');
        // Read and eval library
        var filedata = fs.readFileSync(path.join(__dirname, '/my-hmac.js'),'utf8');
        eval(filedata);
        myHmac = hmac;
    } catch (e) {
        console.log('e: ', e);
        //noHmac
    }
    module.exports = definition();

})('HmacAuthorization', function () {
    return HmacAuthorization;
});

