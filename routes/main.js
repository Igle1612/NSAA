const express = require('express')
const router = express.Router()
const passport = require('passport')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const fortune = require('fortune-teller')
const { ExtractJwt } = require('passport-jwt')
const JwtStrategy = require('passport-jwt').Strategy

router.use(cookieParser())

const cookieExtractor = function (req) {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['jwt'];
    console.log(token)
  }
  return token;
};
passport.use('jwt', new JwtStrategy({
  jwtFromRequest: cookieExtractor, // extract JWT from cookie named 'jwt'
  secretOrKey: global.jwtSecret // replace with your own secret key
}, function (jwtPayload, done) {
  // Here you can verify the JWT payload and extract user data if needed
  const user = { 
    username: jwtPayload.username,
    description: 'a user authenticated via JWT'
  }
  return done(null, user)
}))

// middleware to check if user is authenticated
const isAuthenticated = (req, res, next) => {
  passport.authenticate('jwt', { session: false }, (err, user, info) => {
    console.log(user)
    if (err) {
        console.log("Error")
        return next(err)
    }
    if (!user) {
        console.log("Not user")
        return res.status(401).json({ message: 'Unauthorized' })
    }
    req.user = user
    return next()
  })(req, res, next)
}

// fortune teller route
router.get('/', isAuthenticated, (req, res) => {
  const adage = fortune.fortune()
  console.log(`Hello ${req.user.email}`)
  res.send(`Hello ${req.user.username}, here's your adage: ${adage}`)
})

module.exports = router