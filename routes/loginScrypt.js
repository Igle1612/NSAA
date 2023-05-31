var express = require("express")
var router = express.Router()
const passport = require('passport')
const path = require('path')
const jwt = require('jsonwebtoken')
const fs = require('fs')
const scryptMcf = require('scrypt-mcf')

//router.use(express.static(path.join(__dirname, 'utils')));

router.get('/', (req, res) => {
    res.sendFile('loginScrypt.html', { root: path.join(__dirname, '../frontend') })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
})

router.post('/', 
  passport.authenticate('username-password', { failureRedirect: '/login', session: false }), // we indicate that this endpoint must pass through our 'username-password' passport strategy, which we defined before
  (req, res) => {

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

    res.redirect('/')
  }
)

/*router.post('/', async (req, res) => {
  const { username, password } = req.body

  const users = JSON.parse(fs.readFileSync('./data/users.json'))
  const user = users.users.find(u => u.username === req.body.username)
  
  console.log(password)
  console.log(user.password)

  if (!user) {
    return res.status(401).send('Invalid username or password')
  }
  
  const isValidPassword = await scryptMcf.verify(password, user.password);
  
  console.log(isValidPassword)

  if (!isValidPassword) {
    return res.status(401).send('Invalid username or password');
  }

  const jwtClaims = {
    sub: user.username,
    iss: 'localhost:3000',
    aud: 'localhost:3000',
    exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
    role: 'user',
  };

  const token = jwt.sign(jwtClaims, global.jwtSecret);
  res.cookie('jwt', token, { httpOnly: true, secure: true });
  console.log(`Token sent. ${token}`);
  console.log(`Token secret ${global.jwtSecret.toString('base64')}`);
  res.redirect('/');
})*/

module.exports = router