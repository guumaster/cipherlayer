var log = require('../logger/service.js');
var config = require(process.cwd() + '/config.json');
var tokenMng = require('../managers/token');

function decodeToken (req, res, next){
    var accessToken = req.auth.substring(config.authHeaderKey.length);
    req.accessToken = accessToken;
    try{
        tokenMng.getAccessTokenInfo (accessToken, function(err, tokenInfo) {
            if (err) {
                if (err.err === 'accesstoken_expired') {
                    log.error({err: 'expired_access_token', des: accessToken});
                    res.send(401, {err: 'expired_access_token', des: 'access token expired'});
                    return next(false);
                }
                log.error({err: 'invalid_access_token', des: accessToken});
                res.send(401, {err: 'invalid_access_token', des: 'unable to read token info'});
                return next(false);
            } else {
                req.tokenInfo = tokenInfo;
                return next();
            }
        });
    } catch (ex){
        res.send(403, {
            err: "invalid_token",
            des: "invalid authorization header"
        });
        next(false);
    }
}

module.exports = decodeToken;
