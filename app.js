//Modules
const express = require('express'),
    bunyan = require('bunyan'),
    bodyParser = require('body-parser'),
    session = require('express-session'),
    fetch = require("node-fetch"),
    crypto = require('crypto');

const passport = require('passport');    

require('./lib/passport');    



//Load values from .env file
require('dotenv').config();

exports.initialize = function() {
    return passport.initialize();
  };
  




const app = express();
const log = bunyan.createLogger({ name: 'Authorization Code Flow' });

app.use(passport.initialize())
app.use(passport.session())

app.use(express.static('public'));
// app.use(session({ secret: 'ssshhhhh' }));
app.use(session({
    secret: 'emr',
    accessToken:'',
    cookie: { path: '/', secure: false, maxAge: null }
  }))
  

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

app.set('view engine', 'ejs');

function base64URLEncode(str) {
    return str.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}



app.get('/auth/example',
  passport.authenticate('oauth2'));

app.get('/auth/example/callback',
  passport.authenticate('oauth2', { failureRedirect: '/login' }),
  function(req, res) {
      console.log(req);
    // Successful authentication, redirect home.
    res.redirect('/');
  });



app.get('/', (req, res) => {

    //generate a code verifier
    req.session.code_verifier = base64URLEncode(crypto.randomBytes(43));
    //get code challenge
    req.session.code_challenge = base64URLEncode(crypto.createHash('sha256').update(req.session.code_verifier).digest());

    res.render('index', { code_verifier: req.session.code_verifier, code_challenge: req.session.code_challenge });
});

//Set 1: Ask the authorization code
app.get('/get/the/code', (req, res) => {

    log.info(req.session.code_challenge);

    //const Authorization_Endpoint = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/authorize`;
    const Authorization_Endpoint = "http://localhost:4444/oauth2/auth";
    const Response_Type = 'code';
    const Client_Id = process.env.CLIENT_ID;
    //const Redirect_Uri = 'http://localhost:1234/callbacks';
    const Redirect_Uri = 'http://localhost:8030/give/me/the/code';
    //const Scope = 'https://graph.microsoft.com/User.Read';
    const Scope = 'users.write+users.read+users.edit+users.delete+offline';
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

//Step 3: Exchange the code for a token
app.post('/exchange/the/code/for/a/token', (req, res) => {

    //const Token_Endpoint = `https://login.microsoftonline.com/${process.env.TENANT_ID}/oauth2/v2.0/token`;
    const Token_Endpoint = "http://localhost:4444/oauth2/token";
    const Grant_Type = 'authorization_code';
    const Code = req.body.code;
    const Client_Id = process.env.CLIENT_ID;
    const Redirect_Uri = 'http://localhost:8030/give/me/the/code';
    //const Client_Id = process.env.CLIENT_ID;
    //const Client_Secret = process.env.CLIENT_SECRET;
    const Scope = 'users.write+users.read+users.edit+users.delete+offline';
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

app.listen(8030);