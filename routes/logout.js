var express = require("express")
var router = express.Router()

router.get('/', (req, res) => {
    res.cookie('jwt', '', { expires: new Date(0) })
    res.redirect('/')
})

module.exports = router