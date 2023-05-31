var express = require("express")
var router = express.Router()
const passport = require('passport')
const path = require('path')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')

router.use(express.static(path.join(__dirname, 'frontend')));

router.get('/',
    (req, res) => {
      res.sendFile('login.html', { root: path.join(__dirname, '../frontend') })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
    }
)

router.post('/', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {
    console.log("Username:" + req.body.username)
    console.log("Password:" + req.body.password) 
    const jwtClaims = {
      sub: req.user.username,
      iss: 'localhost:3000',
      aud: 'localhost:3000',
      exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
      role: 'user', // just to show a private JWT field
      exam: 'Iglesias'
    }
    
    // Generate a signed json web token.
    const token = jwt.sign(jwtClaims, global.jwtSecret)

    res.cookie('jwt', token, { httpOnly: true, secure: true})

    // And let us log a link to the jwt.io debugger, for easy checking/verifying:
    console.log(`Token sent. Debug at https://jwt.io/?value=${token}`)
    console.log(`Token secret (for verifying the signature): ${global.jwtSecret.toString('base64')}`)

    res.redirect('/')
  }
)

module.exports = router