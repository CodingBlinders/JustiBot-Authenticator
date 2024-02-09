const User = require('../models/User');
const bcrypt = require('bcryptjs');


module.exports.register = async (req, res, next) => {
    console.log(req);
    try {
      const { email, password, name, createdAt } = req.body;
      // Set the default role to "user"
      const role = "user";
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: "User already exists" });
      }
      const user = await User.create({ email, password, name, createdAt, role });
    
      res
        .status(201)
        .json({ message: "User signed up successfully", success: true, user });
      next();
    } catch (error) {
      console.error(error);
    }
  };