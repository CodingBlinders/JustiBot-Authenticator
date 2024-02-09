const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const password = 'myPassword';
const saltRounds = 12; // Changed salt rounds to match the value used in hashing

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String, // Add Google ID field
    email: String,    // Add email field
    displayName: String, // Add display name field
    picture : String, // Add picture field
    role : String, // Add role field
});

userSchema.pre("save", async function (next) {
    try {
        // Only hash the password if it has been modified (or is new)
        if (!this.isModified('password')) {
            return next();
        }
        // Generate a salt
        const salt = await bcrypt.genSalt(saltRounds);
        // Hash the password along with the new salt
        const hashedPassword = await bcrypt.hash(this.password, salt);
        // Replace the plaintext password with the hashed password
        this.password = hashedPassword;
        next();
    } catch (error) {
        next(error);
    }
});

const User = mongoose.model('User', userSchema);

module.exports = User;
