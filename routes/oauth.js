var express = require("express")
var router = express.Router()
const passport = require('passport')
const path = require('path')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const axios = require('axios')
require('dotenv').config()

const { generateToken } = require("../utils/tokenmanagement");

router.get('/', async (req, res) => { // watchout the async definition here. It is necessary to be able to use async/await in the route handler
  /**
   * 1. Retrieve the authorization code from the query parameters
   */
  const code = req.query.code // Here we have the received code
  if (code === undefined) {
    const err = new Error('no code provided')
    err.status = 400 // Bad Request
    throw err
  }

  /**
   * 2. Exchange the authorization code for an actual access token at OUATH2_TOKEN_URL
   */
  const tokenResponse = await axios.post(process.env.OAUTH2_TOKEN_URL, {
    client_id: process.env.OAUTH2_CLIENT_ID,
    client_secret: process.env.OAUTH2_CLIENT_SECRET,
    code
  })

  console.log(tokenResponse.data) // response.data contains the params of the response, including access_token, scopes granted by the use and type.

  // Let us parse them ang get the access token and the scope
  const params = new URLSearchParams(tokenResponse.data)
  const accessToken = params.get('access_token')
  const scope = params.get('scope')

  // if the scope does not include what we wanted, authorization fails
  if (scope !== 'user:email') {
    const err = new Error('user did not consent to release email')
    err.status = 401 // Unauthorized
    throw err
  }

  /**
   * 3. Use the access token to retrieve the user email from the USER_API endpoint
   */
  const userDataResponse = await axios.get(process.env.USER_API, {
    headers: {
      Authorization: `Bearer ${accessToken}` // we send the access token as a bearer token in the authorization header
    }
  })
  console.log(userDataResponse.data)

  /**
   * 4. Create our JWT using the github email as subject, and set the cookie.
   */
    const token = generateToken("Hola") // just copy and paste or invoke the function you used for creating the JWT for a user logging in with username and password.
  
    res.cookie('jwt', token, { httpOnly: true, secure: true})
  
    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${global.jwtSecret.toString('base64')}`)

    res.redirect('http://localhost:3000/')
})

module.exports = router