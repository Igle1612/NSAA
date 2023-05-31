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

module.exports = {
    generateToken
};