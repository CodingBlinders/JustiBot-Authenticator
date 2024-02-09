const passport = require('passport');

// Google OAuth authentication handler
exports.googleAuth = passport.authenticate('google', { scope: ['profile', 'email'] });
