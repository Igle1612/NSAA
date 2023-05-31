var express = require("express")
var router = express.Router()
const passport = require('passport')
const path = require('path')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const axios = require('axios')
require('dotenv').config()

const { generateToken } = require("../utils/tokenmanagement");

router.get('/error', (req, res) => res.send('Unknown Error'))

router.get('/github', passport.authenticate('github',{ scope: [ 'user:email' ] }));

router.get('/github/callback', passport.authenticate('github', { failureRedirect: '/auth/error' }),
function(req, res) {
    const token = generateToken("Hola")
    res.cookie('jwt', token, { httpOnly: true, secure: true})
    res.redirect('http://localhost:3000/');
});

module.exports = router