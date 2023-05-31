async function main() {
  const express = require('express')
  const logger = require('morgan')
  const passport = require('passport')
  const session = require('express-session')
  const LocalStrategy = require(`passport-local`).Strategy
  const jwt = require('jsonwebtoken')
  const jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits
  const cookieParser = require('cookie-parser')
  const scryptMcf = require('scrypt-mcf')
  const { checkIfUserExists, insertUser } = require('./utils/usermanagement')
  const fs = require('fs')
  const GitHubStrategy = require('passport-github2').Strategy;
  const OpenIDConnectStrategy  = require('passport-openidconnect').Strategy;
  const GoogleStrategy = require('passport-google-oidc').Strategy;
  const Issuer = require('openid-client').Issuer;
  require('dotenv').config()
  const { generateToken } = require("./utils/tokenmanagement");

  const app = express()
  const port = 3000
  global.jwtSecret = require('crypto').randomBytes(16) // 16*8=256 random bits 


  passport.use('username-password', new LocalStrategy(
    {
      usernameField: 'username',  // it MUST match the name of the input field for the username in the login HTML formulary
      passwordField: 'password',  // it MUST match the name of the input field for the password in the login HTML formulary
      session: false // we will store a JWT in the cookie with all the required session data. Our server does not need to keep a session, it's going to be stateless
    },
    async function (username, password, done) {

      console.log(username)
      console.log(password)

      const users = JSON.parse(fs.readFileSync('./data/users.json'))
      const user1 = users.users.find(u => u.username === username)

      if (!user1) {
        return done(null, false)
      }

      if (await scryptMcf.verify(password, user1.password)) {
        const user = {
          username: user1,
          description: 'the only user that deserves to contact the fortune teller'
        }
        return done(null, user) // the first argument for done is the error, if any. In our case there is no error, and so we pass null. The object user will be added by the passport middleware to req.user and thus will be available there for the next middleware and/or the route handler 
      }
      return done(null, false)  // in passport returning false as the user object means that the authentication process failed. 
    }
  ))

  passport.serializeUser(function (user, done) {
    return done(null, user)
  })

  // The returned passport user is just the user object that is stored in the session
  passport.deserializeUser(function (user, done) {
    return done(null, user)
  })

  passport.use('username-password-register', new LocalStrategy(
    {
      usernameField: 'username',
      passwordField: 'password',
      session: false
    },
    async function (username, password, done) {
      console.log('Almenys fa algu')
      // check if user exists on the DB
      const userExists = checkIfUserExists(username)

      if (userExists) {
        // cannot register as user already exist
        return done(null, false)
      } else {
        // hash user password
        const hashedPwd = await scryptMcf.hash(password)
        // insert user into db
        await insertUser(username, hashedPwd)

        const user = {
          username: username,
          description: 'the only user that deserves to contact the fortune teller'
        }

        return done(null, user)
      }
    }
  ))

  passport.use(new GitHubStrategy({
    clientID: process.env.OAUTH2_CLIENT_ID,
    clientSecret: process.env.OAUTH2_CLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/github/callback"
  },
    function (accessToken, refreshToken, profile, done) {
      return done(null, profile);
    }
  ));

  app.use(session({
    secret: require('crypto').randomBytes(32).toString('base64url'), // This is the secret used to sign the session cookie. We are creating a random base64url string with 256 bits of entropy.
    resave: false, // Default value is true (although it is going to be false in the next major release). We do not need the session to be saved back to the session store when the session has not been modified during the request.
    saveUninitialized: false // Default value is true (although it is going to be false in the next major release). We do not need sessions that are "uninitialized" to be saved to the store
  }))

  // 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
  /*const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER)
  
  // 2. Setup an OIDC client/relying party.
  const oidcClient = await new oidcIssuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    client_secret: process.env.OIDC_CLIENT_SECRET,
    redirect_uris: [process.env.OIDC_CALLBACK_URL],
    response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
  })*/

  passport.use( "oidc" , new GoogleStrategy({
    clientID: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/oidc/cb', 
  },
  function verify(issuer, profile, cb) {
    const user = {
        id: profile.id,
        name: profile.displayName //profile.displayName
    }
    return cb(null, user);
  }
));
  
  /*passport.use('oidc', new OpenIDConnectStrategy({
    client: oidcClient,
    usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
  }, (tokenSet, userInfo, done) => {
    console.log(tokenSet, userInfo)
    if (tokenSet === undefined || userInfo === undefined) {
      return done('no tokenSet or userInfo')
    }
    return done(null, userInfo)
  }))*/

  app.use(express.urlencoded({ extended: true })) // needed to retrieve html form fields (it's a requirement of the local strategy)
  app.use(passport.initialize())  // we load the passport auth middleware to our express application. It should be loaded before any route.

  app.use(logger('dev'))
  app.use(cookieParser())

  var mainRouter = require('./routes/main.js')
  app.use("/", mainRouter);

  var loginRouter = require('./routes/login.js')
  app.use("/login", loginRouter);

  var loginSRouter = require('./routes/loginScrypt.js')
  app.use("/loginScrypt", loginSRouter);

  var loginOauth = require('./routes/oauth.js')
  app.use("/oauth2cb", loginOauth)

  var loginOauthPass = require('./routes/oauthpass.js')
  app.use("/auth", loginOauthPass)

  app.get('/oidc/login', passport.authenticate('oidc', {scope: 'openid email profile'}))

  app.get('/oidc/cb', passport.authenticate('oidc', { failureRedirect: '/login', failureMessage: true }), (req, res) => {

    // 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
    /*const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER)

    // 2. Setup an OIDC client/relying party.
    const oidcClient = new oidcIssuer.Client({
        client_id: process.env.OIDC_CLIENT_ID,
        client_secret: process.env.OIDC_CLIENT_SECRET,
        redirect_uris: [process.env.OIDC_CALLBACK_URL],
        response_types: ['code'] // code is use for Authorization Code Grant; token for Implicit Grant
    })

    passport.use('oidc', new OpenIDConnectStrategy({
        issuer: oidcIssuer,
        client: oidcClient,
        usePKCE: false // We are using standard Authorization Code Grant. We do not need PKCE.
    }, (tokenSet, userInfo, done) => {
        console.log(tokenSet, userInfo)
        if (tokenSet === undefined || userInfo === undefined) {
            return done('no tokenSet or userInfo')
        }
        return done(null, userInfo)
    }))*/

    /**
   * Create our JWT using the req.user.email as subject, and set the cookie.
   */
    const token = generateToken("Hola") // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password.
  
    res.cookie('jwt', token, { httpOnly: true, secure: true})
  
    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${global.jwtSecret.toString('base64')}`)

    res.redirect('http://localhost:3000/') // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password. The only difference is that now the sub claim will be set to req.user.email
  })

  //var loginOIDC = require('./routes/oidc.js')
  //app.use("/oidc", loginOIDC)

  var registerRouter = require('./routes/register.js')
  app.use("/register", registerRouter)

  var logoutRouter = require('./routes/logout')
  const { config } = require('dotenv')
  app.use("/logout", logoutRouter)

  /** Error handler */
  app.use(function (err, req, res, next) {
    console.error(err.stack)
    res.status(500).send('Something broke!')
  })

  app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`)
  })
}
main().catch(e => { console.log(e) })