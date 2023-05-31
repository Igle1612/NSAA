var express = require("express")
var router = express.Router()
const passport = require('passport')
const path = require('path')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser')
const fs = require('fs')
const { hash } = require("scrypt-mcf")
const scryptMcf = require('scrypt-mcf')
const crypto = require('crypto');

router.use(express.static(path.join(__dirname, 'frontend')));

router.get('/',
    (req, res) => {
        console.log('Getting html')
        res.sendFile('register.html', { root: path.join(__dirname, '../frontend') })  // we created this file before, which defines an HTML form for POSTing the user's credentials to POST /login
    }
)

/*router.post('/', 
    passport.authenticate('username-password-register', { failureRedirect: '/register', session: false }), 
    (req, res) => {
    // perform register authentication, if successful redirect main page
})*/

router.post('/', async (req, res) => {
    const { username, password } = req.body

    const params = {ln: 17, r: 8, p: 1}

    const users = JSON.parse(fs.readFileSync('./data/users.json'))
 
    const user = users.users.find(u => u.username == req.body.username)

    if(user) {
        return res.status(409).send('User exists')
    }

    const salt = crypto.randomBytes(16).toString('hex');

    const hashPswd = await scryptMcf.hash(password, {params})

    const newUser = {
        "username": username,
        "password": hashPswd,
        "salt": salt
    };

    users.users.push(newUser)

    fs.writeFileSync('./data/users.json', JSON.stringify(users, null, 2))

    res.redirect('/login')
})

module.exports = router