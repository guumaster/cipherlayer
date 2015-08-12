var FacebookStrategy = require('passport-facebook').Strategy;

var log = require('../logger/service');
var tokenManager = require('../managers/token');
var userDao = require('../managers/dao');
var userManager = require('../managers/user')();
var config = require(process.cwd() + '/config.json');

function createFacebookStrategy() {

    return new FacebookStrategy({
        clientID: config.facebook.clientId,
        clientSecret: config.facebook.clientSecret,
        callbackURL: config.facebook.callbackURL,
        passReqToCallback: true
    }, function(req, accessToken, refreshToken, profile, done) {
        var data = {
            accessToken: accessToken,
            refreshToken: refreshToken,
            profile: profile
        };
        done(null, data);
    });
}

function facebookCallback(req, res, next) {
    var facebookData = req.user;
    var profile = facebookData.profile;

    userDao.getFromUsername(profile.email, function(err, foundUser) {
        if(err){
            if(err.message == userDao.ERROR_USER_NOT_FOUND) {
                var tokenData = {
                    accessToken: facebookData.accessToken,
                    refreshToken: facebookData.refreshToken
                };
                tokenManager.createAccessToken(profile.id, tokenData, function(err, token){
                    var returnProfile = {
                        name: profile.name.givenName,
                        lastname: profile.name.familyName,
                        email: profile.email,
                        facebook: token
                    };
                    res.send(203, returnProfile);
                    return next(false);
                });
            }

            res.send(500, {err:'internal_error', des:'There was an internal error matching facebook profile'});
            return next(false);
        }


        var platform = {
            platform:'facebook',
            accessToken: facebookData.accessToken
        };

        if (facebookData.refreshToken) {
            platform.refreshToken = facebookData.refreshToken;
        }
        if (facebookData.expiresIn) {
            platform.expiry = new Date().getTime() + facebookData.expiresIn * 1000;
        }

        userManager.setPlatformData(foundUser._id, 'facebook', platform, function(err) {
            if (err) {
                log.error({err:err}, 'error updating facebook tokens into user '+foundUser._id+'');
            }
            var data = {};
            if(foundUser.roles) {
                data = {"roles": foundUser.roles};
            }

            tokenManager.createBothTokens(foundUser._id, data , function(err, tokens) {
                if(err) {
                    res.send(409,{err: err.message});
                } else {
                    tokens.expiresIn = config.accessToken.expiration * 60;
                    res.send(200,tokens);
                }
                return next();
            });
        });
    });
}

function addRoutes(server, passport) {
	if(!config.facebook){
		return;
	}

    log.info('Adding Facebook routes');
    var facebookStrategy = createFacebookStrategy();
	passport.use(facebookStrategy);
    server.get('/auth/facebook', passport.authenticate('facebook', {scope: config.facebook.scope, accessType: 'offline', state: new Date().getTime() } ));
    server.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/auth/error', session: false} ), facebookCallback);
}

module.exports = {
    addRoutes: addRoutes
};
