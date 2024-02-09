const express = require('express');
const passport = require('passport');
const router = express.Router();
const googleController = require('../controllers/googleController');

router.get('/', googleController.googleAuth);

router.get('/callback', passport.authenticate('google', {
    successRedirect: '/',
    failureRedirect: '/login'
  }));


module.exports = router;
