const passport = require('passport')
const OAuth2Strategy = require('passport-oauth2');

// var Strategy = require('passport-http-bearer').Strategy;

passport.serializeUser(function(user, done) {
    done(null, user);
  });
  
  passport.deserializeUser(function(user, done) {
    done(null, user);
  });

//   passport.use(new Strategy(
//     function(token, cb) {
//       return 'ZcwjGZdCB1IUVVmCGPSaLB3V4ghHEo';
//     }));



passport.use(new OAuth2Strategy({
    authorizationURL: "http://localhost:4444/oauth2/auth",
    tokenURL: "http://localhost:4444/oauth2/token",
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
   // callbackURL: "http://localhost:8030/auth/example/callback"
   callbackURL:  "http://localhost:8030/give/me/the/code"
  },
  function(accessToken, refreshToken, profile, cb) {
//     User.findOrCreate({ exampleId: profile.id }, function (err, user) {
//       return cb(err, user);
//     });
//   }

return done(null, profile);
  }
));


// passport.use(new BearerStrategy(
//   function(token, done) {
//     console.log(profile);
//   }
//));