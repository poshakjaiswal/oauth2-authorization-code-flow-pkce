//Modules
const express = require('express'),
    bunyan = require('bunyan'),
    bodyParser = require('body-parser'),
    session = require('express-session'),
    fetch = require("node-fetch"),
    crypto = require('crypto');
    // mongoose = require('mongoose'),
    // Schema = mongoose.Schema,
    // UserSchema = new Schema({ any: Object }),
    // UserModel = mongoose.model('Users', UserSchema);    

 const { configureAuthForServer, createHydraClientIfNecessary } = require("./lib/serverAuth");

const passport = require('passport');   

//const  greytHrStrategy = require('./lib/greythr-strategy'); //greythr-strategy.js  

//require('./lib/passport');    



//Load values from .env file
require('dotenv').config();



const app = express();
const log = bunyan.createLogger({ name: 'Authorization Code Flow' });


app.use(express.static('public'));
// app.use(session({ secret: 'ssshhhhh' }));
app.use(session({
    secret: 'emr',
    accessToken:'',
    cookie: { path: '/', secure: false, maxAge: null }
  }))
  

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// app.use(passport.initialize());
// app.use(passport.session());


configureAuthForServer(app);


app.set('view engine', 'ejs');

function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

app.get("/callback", passport.authenticate("oauth2"), (req, res) => {
  // After success, redirect to the page we came from originally
  res.redirect(req.session.redirectTo || "/");
});


// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Meetup profile is
//   serialized and deserialized.
// passport.serializeUser(function(user, done) {
//     done(null, user);
//   });
  
//   passport.deserializeUser(function(obj, done) {
//     done(null, obj);
//   });
  
  // Use the MeetupStrategy within Passport.
  //   Strategies in passport require a `verify` function, which accept
  //   credentials (in this case, a token, tokenSecret, and Meetup profile), and
  //   invoke a callback with a user object.
  // passport.use(new greytHrStrategy({
  //     clientID: process.env.CLIENT_ID,
  //     clientSecret: process.env.CLIENT_SECRET,
  //     // callbackURL: "https://meetup.compiledmcr.com/auth/meetup/callback"
  //     callbackURL: "http://localhost:8030/auth/greythr/callback"
  //   },
  //   function(token, tokenSecret, profile, done) {
  //     // asynchronous verification, for effect...
  //     process.nextTick(function () {
  //       console.log("Verification Log: ", { token, tokenSecret, profile });
  //       let user = new UserModel;
  //       user.token = token;
  //       user.tokenSecret = tokenSecret;
  //       user.profile = profile;
  //       user.save();
  //       // To keep the example simple, the user's Meetup profile is returned to
  //       // represent the logged-in user.  In a typical application, you would want
  //       // to associate the Meetup account with a user record in your database,
  //       // and return that user instead.
  //       return done(null, profile);
  //     });
  //   }
  // ));

  // GET /auth/meetup
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Meetup authentication will involve redirecting
//   the user to meetup.com.  After authorization, Meetup will redirect the user
//   back to this application at /auth/meetup/callback
// app.get('/auth/greythr',
// passport.authenticate('greythr'),
// function(req, res){
//   // The request will be redirected to Meetup for authentication, so this
//   // function will not be called.
// });

// GET /auth/meetup/callback
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
// app.get('/auth/greythr/callback', 
// passport.authenticate('greythr', { failureRedirect: '/login' }),
// function(req, res) {
//   res.redirect('/');
// });






// app.get('/auth/example',
//   passport.authenticate('oauth2'));

// app.get('/auth/example/callback',
//   passport.authenticate('oauth2', { failureRedirect: '/login' }),
//   function(req, res) {
//       console.log(req);
//     // Successful authentication, redirect home.
//     res.redirect('/');
//   });



app.get('/', (req, res) => {

    //generate a code verifier
    req.session.code_verifier = base64URLEncode(crypto.randomBytes(43));
    //get code challenge
    req.session.code_challenge = base64URLEncode(crypto.createHash('sha256').update(req.session.code_verifier).digest());

    res.render('index', { code_verifier: req.session.code_verifier, code_challenge: req.session.code_challenge });
});

//Set 1: Ask the authorization code
app.get('/get/the/code', (req, res) => {

  //  passport.authenticate('oauth2', { failureRedirect: '/login' })

    log.info(req.session.code_challenge);

    //const Authorization_Endpoint = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/authorize`;
   // const Authorization_Endpoint = "http://localhost:4444/oauth2/auth";
   //const Authorization_Endpoint = "http://idp.gtchat.gr8hr3.com/uas/hydra/login";
   //https://masterdemo1.gtchat.gr8hr3.com/uas/portal/auth/login  //first endpoint
    const Authorization_Endpoint = "https://hydra.gtchat.gr8hr3.com/oauth2/auth";
    const Response_Type = 'code';
    const Client_Id = process.env.CLIENT_ID;
    //const Redirect_Uri = 'http://localhost:1234/callbacks';
    const Redirect_Uri = 'https://f028-2405-201-a416-c01c-cc3f-65a6-d553-4afe.ngrok.io/uas/portal/auth/callback';
    //const Scope = 'https://graph.microsoft.com/User.Read';
    const Scope = 'openid+offline';
    const State = 'ThisIsMyStateValue';
    const Code_Challenge = req.session.code_challenge;

    //http://localhost:4444/oauth2/auth?client_id=myclient&prompt=consent&redirect_uri=http%3A%2F%2Fexample.com&response_type=code&scope=users.write+users.read+users.edit&state=XfFcFf7KL7ajzA2nBY%2F8%2FX3lVzZ6VZ0q7a8rM3kOfMM%3D

   // http://localhost:4444/oauth2/auth?client_id=poshak&redirect_uri=http%3A%2F%2Flocalhost%3A1234%2Fcallbacks&response_type=code&scope=users.write+users.read+users.edit+users.delete+offline&state=4ZlTumSS1Oe3Vi6EtixWz0%2FYVl26HZJj1NGTu1nkffQ%3D

    let url = `${Authorization_Endpoint}?client_id=${Client_Id}&prompt=consent&redirect_uri=${Redirect_Uri}&response_type=code&scope=${Scope}&state=${State}&access_id=4d2b53544a4c6b467739714653514739635a356d614679347535376c4c464c5a6d77524a432f464b6e61453d`;

    log.info(url);

    res.redirect(url);

});

//Set 1: Ask the authorization code
app.get('/get/the/code1', (req, res) => {

    passport.authenticate('oauth2', { failureRedirect: '/login' })

    log.info(req.session.code_challenge);

    //const Authorization_Endpoint = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/authorize`;
   // const Authorization_Endpoint = "http://localhost:4444/oauth2/auth";
   //const Authorization_Endpoint = "http://idp.gtchat.gr8hr3.com/uas/hydra/login";
    const Authorization_Endpoint = "https://hydra.gtchat.gr8hr3.com/oauth2/auth";
    const Response_Type = 'code';
    const Client_Id = process.env.CLIENT_ID;
    //const Redirect_Uri = 'http://localhost:1234/callbacks';
    const Redirect_Uri = 'https://f028-2405-201-a416-c01c-cc3f-65a6-d553-4afe.ngrok.io/uas/portal/auth/callback';
    //const Scope = 'https://graph.microsoft.com/User.Read';
    const Scope = 'openid+offline';
    const State = 'ThisIsMyStateValue';
    const Code_Challenge = req.session.code_challenge;

    //http://localhost:4444/oauth2/auth?client_id=myclient&prompt=consent&redirect_uri=http%3A%2F%2Fexample.com&response_type=code&scope=users.write+users.read+users.edit&state=XfFcFf7KL7ajzA2nBY%2F8%2FX3lVzZ6VZ0q7a8rM3kOfMM%3D

   // http://localhost:4444/oauth2/auth?client_id=poshak&redirect_uri=http%3A%2F%2Flocalhost%3A1234%2Fcallbacks&response_type=code&scope=users.write+users.read+users.edit+users.delete+offline&state=4ZlTumSS1Oe3Vi6EtixWz0%2FYVl26HZJj1NGTu1nkffQ%3D

    let url = `${Authorization_Endpoint}?client_id=${Client_Id}&prompt=consent&redirect_uri=${Redirect_Uri}&response_type=code&scope=${Scope}&state=${State}`;

    log.info(url);

    res.redirect(url);

});

//Step 2: Get the code from the URL
app.get('/give/me/the/code', (req, res) => {
    //before continue, you should check that req.query.state is the same that the state you sent
    res.render('exchange-code', { code: req.query.code, state: req.query.state });
});


app.get('/uas/portal/auth/callback', (req, res) => {
    //before continue, you should check that req.query.state is the same that the state you sent
    res.render('exchange-code', { code: req.query.code, state: req.query.state });
});


//Step 3: Exchange the code for a token
app.post('/exchange/the/code/for/a/token', (req, res) => {

    //const Token_Endpoint = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/token`;
    const Token_Endpoint = "https://hydra.gtchat.gr8hr3.com/oauth2/token";
    const Grant_Type = 'authorization_code';
    const Code = req.body.code;
    const Client_Id = process.env.CLIENT_ID;
    const Redirect_Uri = 'https://f028-2405-201-a416-c01c-cc3f-65a6-d553-4afe.ngrok.io/uas/portal/auth/callback';
    //const Client_Id = process.env.CLIENT_ID;
    const Client_Secret = process.env.CLIENT_SECRET;
    const Scope = 'openid+offline';
    //const Code_Verifier = req.session.code_verifier;

   // log.info(Code_Verifier);

    let body = `grant_type=${Grant_Type}&client_id=${Client_Id}&code=${Code}&redirect_uri=${encodeURIComponent(Redirect_Uri)}`;

    //let body = `${Authorization_Endpoint}?grant_type=${Grant_Type}?client_id=${Client_Id}&prompt=consent&redirect_uri=${Redirect_Uri}&response_type=code&scope=${Scope}&state=${State}`;

    log.info(`Body: ${body}`);

    ///////
    //var myHeaders = new Headers();
    //myHeaders.append("Content-Type", "application/x-www-form-urlencoded");

    var urlencoded = new URLSearchParams();
    urlencoded.append("grant_type", Grant_Type);
    urlencoded.append("code", Code);
    //urlencoded.append("refresh_token", "velit dolor anim laborum incididunt");
    urlencoded.append("redirect_uri",Redirect_Uri);
    urlencoded.append("client_id", Client_Id);
    urlencoded.append("client_secret", Client_Secret);

    /////////

    fetch(Token_Endpoint, {
        method: 'POST',
        headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
        body: urlencoded,
    }).then(async response => {

        let json = await response.json();
        res.render('access-token', { token: JSON.stringify(json, undefined, 2) }); //you shouldn't share the access token with the client-side

    }).catch(error => {
        log.error(error.message);
    });


    // fetch(Token_Endpoint, {
    //     method: 'POST',
    //     body: body,
    //     headers: {
    //         'Content-Type': 'application/x-www-form-urlencoded'
    //     }
    // }).then(async response => {

    //     let json = await response.json();
    //     res.render('access-token', { token: JSON.stringify(json, undefined, 2) }); //you shouldn't share the access token with the client-side

    // }).catch(error => {
    //     log.error(error.message);
    // });
});

//Step 4: Call the protected API
app.post('/call/ms/graph', (req, res) => {

    let access_token = JSON.parse(req.body.token).access_token;

    const Microsoft_Graph_Endpoint = 'https://graph.microsoft.com/beta';
    const Acction_That_I_Have_Access_Because_Of_My_Scope = '/me';

    //Call Microsoft Graph with your access token
    fetch(`${Microsoft_Graph_Endpoint}${Acction_That_I_Have_Access_Because_Of_My_Scope}`, {
        headers: {
            'Authorization': `Bearer ${access_token}`
        }
    }).then(async response => {

        let json = await response.json();
        res.render('calling-ms-graph', { response: JSON.stringify(json, undefined, 2) });
    });
});

app.listen(8080);