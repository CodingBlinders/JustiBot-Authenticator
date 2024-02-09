require('dotenv').config(); // Load environment variables
const express = require('express');
const passport = require('passport');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('./models/User');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const googleRoutes = require('./routes/googleRoutes');
const bcrypt = require('bcrypt');
const router = express.Router();
var crypto = require('crypto');

const session = require('express-session');

const app = express();
secreatKey = crypto.randomBytes(64).toString('hex');
app.use(session({ secret: secreatKey, resave: false, saveUninitialized: false }));

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.use(passport.initialize());
app.use(passport.session());

MONGO_URL= process.env.MONGO_URL
mongoose.connect(MONGO_URL);

GOOGLE_CLIENT_ID=process.env.GOOGLE_CLIENT_ID;
GOOGLE_CLIENT_SECRET=process.env.GOOGLE_CLIENT_SECRET;
callbackURL=process.env.CALLBACK_URL;

// Passport Google OAuth strategy

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: callbackURL
}, async (accessToken, refreshToken, profile, done) => {
    try {
        // Check if the user already exists in the database
        const existingUser = await User.findOne({ googleId: profile.id });
        if (existingUser) {
            // If the user already exists, simply return the user
            return done(null, existingUser);
        }
        // If the user doesn't exist, create a new user and save it to the database
        const newUser = new User({
            googleId: profile.id,
            email: profile.emails[0].value,
            displayName: profile.displayName,
            picture: profile.picture,
            // You can save other relevant user information from the profile as needed
        });
        console.log(profile);
        await newUser.save();
        return done(null, newUser);
    } catch (err) {
        return done(err);
    }
}));


passport.use(new LocalStrategy(
    { usernameField: 'email' }, // Specify the field name for the email
    async (email, password, done) => {
        try {
            const user = await User.findOne({ email });
            if (!user) {
                return done(null, false, { message: 'Incorrect email or password.' });
            }

            const auth = await bcrypt.compare(password, user.password);
            if (!auth) {
                return done(null, false, { message: 'Incorrect email or password.' });
            }

            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// Handle login route
app.post('/login/password', (req, res, next) => {
    console.log(req.body); // Log the request body

    // Authenticate using the local strategy
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            return next(err);
        }
        if (!user) {
            // Authentication failed, redirect to login page with error message
            return res.redirect('/login?error=' + encodeURIComponent(info.message));
        }
        // Authentication successful, log in the user
        req.login(user, (err) => {
            if (err) {
                return next(err);
            }
            // Redirect to the home page or any desired page upon successful login
            return res.redirect('/');
        });
    })(req, res, next);
});

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
        cb(null, { id: user.id, username: user.username, name: user.name });
    });
});

passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
        return cb(null, user);
    });
});

app.get('/validate', (req, res) => {
    if (req.isAuthenticated()) {
      res.json({ authenticated: true, user: req.user });
    } else {
      res.json({ authenticated: false });
    }
});


// Routes
app.use('/auth', authRoutes);
app.use('/user', userRoutes);
app.use('/auth/google', googleRoutes);

app.listen(3001, () => {
    console.log('Server is running on port 3001');
});
