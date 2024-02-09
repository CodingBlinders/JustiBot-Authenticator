const passport = require('passport');


exports.login = passport.authenticate('local', { failureRedirect: '/logind' });

// Route handler for handling authentication success or failure
exports.loginCallback = (req, res) => {
    res.redirect('/');
};
// Logout handler
exports.logout = (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return next(err); // Handle errors here
        }
        // Successful logout actions
        res.redirect('/'); // Or redirect to a different page
    });
};
