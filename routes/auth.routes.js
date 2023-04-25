const express = require('express')
const router = express.Router()

const User = require('../models/User.model')

const pwdRegex = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d@$!%*#?&]{8,}$/

router.get('/signup', (req, res, next) => {
    res.render('auth/signup')
  })

router.post('/signup', async (req, res, next) => {
    try {        
        const potentialUser = await User.findOne({ username: req.body.username })
        if (!potentialUser) {
          if (pwdRegex.test(req.body.password)) {
            const salt = bcryptjs.genSaltSync(13)
            const passwordHash = bcryptjs.hashSync(req.body.password, salt)
            await User.create({ username: req.body.username, passwordHash })
            res.redirect('/auth/login')
          } else {
            res.render('auth/signup', {
              errorMessage: 'Password is not strong enough',
              data: { username: req.body.username },
            })
          }
        } else {
          res.render('auth/signup', {
            errorMessage: 'Username already in use',
            data: { username: req.body.username },
          })
        }
    } catch (error) {
        console.log(error)
    }
})

  router.get('/login', (req, res, next) => {
    res.render('auth/login')
  })

module.exports = router