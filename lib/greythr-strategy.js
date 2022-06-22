'use strict';

var OAuth2Strategy = require('passport-oauth2'),
    InternalOAuthError = require('passport-oauth2').InternalOAuthError,
    util = require('util');

function Strategy(options,verify){
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'http://localhost:4444/oauth2/auth';
  options.tokenURL = options.tokenURL || 'http://localhost:4444/oauth2/token';

  OAuth2Strategy.call(this,options,verify);
  this.name = 'meetup';
  this._refreshURL = options.refreshURL || 'http://localhost:4444/oauth2/token';
  this._oauth2._useAuthorizationHeaderForGET = true;
  this._oauth2._skipUserProfile = false;
}

util.inherits(Strategy, OAuth2Strategy);

module.exports = Strategy;