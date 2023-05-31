const express = require("express")
const session = require('express-session')
const router = express.Router()
const passport = require('passport')
const path = require('path')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const axios = require('axios')
const { Strategy: OpenIDConnectStrategy } = require('passport-openidconnect');
const { Issuer } = require('openid-client');
require('dotenv').config()

const { generateToken } = require("../utils/tokenmanagement");

async function configurePassport() {
    // 1. Download the issuer configuration from the well-known openid configuration (OIDC discovery)
    const oidcIssuer = await Issuer.discover(process.env.OIDC_PROVIDER)

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
    }))
}

configurePassport().catch(e => { console.log(e) })

/*passport.use(
    'oidc',
    new OpenIDConnectStrategy(
      {
        issuer: 'https://accounts.google.com', // Google OIDC issuer URL
        clientID: process.env.OIDC_CLIENT_ID, // Replace with your Google client ID
        clientSecret: process.env.OIDC_CLIENT_SECRET, // Replace with your Google client secret
        authorizationURL: 'https://accounts.google.com/o/oauth2/auth', // Google authorization URL
        tokenURL: 'https://accounts.google.com/o/oauth2/token', // Google token URL
        userInfoURL: 'https://www.googleapis.com/oauth2/v3/userinfo', // Google user info URL
        callbackURL: 'http://localhost:3000/oidc/cb' // Replace with your callback URL
      },
      async (tokenset, userinfo, done) => {
        console.log(tokenSet, userInfo)
        if (tokenSet === undefined || userInfo === undefined) {
            return done('no tokenSet or userInfo')
        }
        return done(null, userInfo)
      }
    )
  );*/

router.get('/login', passport.authenticate('oidc', {scope: 'openid email profile'}))

router.get('/cb', passport.authenticate('oidc', { failureRedirect: '/login/fail', failureMessage: true }), (req, res) => {

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

module.exports = router