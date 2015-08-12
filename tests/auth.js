var cipherlayer = require('../src/cipherlayer.js');
var config = require('../config.json');

var describeLogin = require('./auth/login.js');
var describeUser = require('./auth/user.js');
var describeSf = require('./auth/sf.js');
var describeIn = require('./auth/in.js');
var describeGoogle = require('./auth/google.js');
var describeFacebook = require('./auth/facebook.js');
var describeRenew = require('./auth/renew.js');

var accessTokenSettings = {
    cipherKey: config.accessToken.cipherKey,
    firmKey: config.accessToken.signKey,
    tokenExpirationMinutes: config.accessToken.expiration
};

var refreshTokenSettings = {
    cipherKey: config.refreshToken.cipherKey,
    firmKey: config.refreshToken.signKey,
    tokenExpirationMinutes: config.refreshToken.expiration
};

describe('/auth', function(){
    beforeEach(function(done){
        cipherlayer.start(config.public_port, config.private_port, done);
    });

    afterEach(function(done){
        cipherlayer.stop(done);
    });

    describeLogin.describe(accessTokenSettings, refreshTokenSettings);
    describeUser.describe();
    describeSf.describe(accessTokenSettings, refreshTokenSettings);
    describeIn.describe();
    describeGoogle.describe();
    describeFacebook.describe();
    describeRenew.describe();
});
