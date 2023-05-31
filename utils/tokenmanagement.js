const fs = require('fs')
const jwt = require('jsonwebtoken')
/**
 * Check if user exist on the database
 * @param username
 * @returns {Promise<boolean|*>}
 */

const generateToken = (username) => {
    console.log('Generating token')

    const jwtClaims = {
        sub: username,
        iss: 'localhost:3000',
        aud: 'localhost:3000',
        exp: Math.floor(Date.now() / 1000) + 604800, // 1 week (7×24×60×60=604800s) from now
        role: 'user' // just to show a private JWT field
      }
      
      // Generate a signed json web token.
      const token = jwt.sign(jwtClaims, global.jwtSecret)

      return token
};

const verifyToken = (req, res, next) => {
    const token = req.cookies.user_login;
    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.user = decoded;
        next();
    } catch (err) {
        res.clearCookie('user_login');
        if ((req.path === '/login') || (req.path === '/register')) {
            next();
        } else {
            res.redirect('/login');
        }
    }
};

const redirectHome = (req, res, next) => {
    if (req.user !== undefined) {
        res.redirect('/');
    }
    next()
};

module.exports = {
    generateToken,
    verifyToken,
    redirectHome
};