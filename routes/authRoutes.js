// routes/authRoutes.js
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/User");

module.exports = function (app, passport) {

  // Signup endpoint
  app.post("/signup", async (req, res) => {
    try {
      const { name, email, phone, password } = req.body;

      const existingUser = await User.findOne({ $or: [{ email }, { phone }] });

      if (existingUser) {
        return res
          .status(400)
          .json({ message: "Email or phone number already registered" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);

      const newUser = new User({
        name,
        email,
        phone,
        password: hashedPassword,
      });

      await newUser.save();

      return res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  });

  // Login endpoint
  app.post(
    "/login",
    passport.authenticate("local", { session: false }),
    (req, res) => {
      const token = jwt.sign({ user: req.user }, process.env.JWT_SECRET_KEY);
      res.json({ token });
      // , {
      //   expiresIn: "1h",
      // }
    }
  );

  // Forgot password endpoint
  app.post("/forgot-password", async (req, res) => {
    try {
      const { emailOrPhone } = req.body;

      const user = await User.findOne({
        $or: [{ email: emailOrPhone }, { phone: emailOrPhone }],
      });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      if (user.resetTokenUsed) {
        return res.status(400).json({ message: "Reset token already used" });
      }

      const resetToken = jwt.sign({ user: user._id }, process.env.JWT_SECRET_KEY, {
        expiresIn: "2m",
      });

      // Set reset token flag to true when sending the token
      user.resetTokenUsed = false;
      await user.save();

      // Send resetToken to the frontend along with the success message
      return res
        .status(200)
        .json({ message: "Token sent successfully", resetToken });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  });

  // Reset password endpoint
  app.post("/reset-password", async (req, res) => {
    try {
      const { resetToken, newPassword, confirmPassword } = req.body;

      if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: "Passwords do not match" });
      }

      const decodedToken = jwt.verify(resetToken, process.env.JWT_SECRET_KEY);

      const user = await User.findById(decodedToken.user);

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      // Check if the reset token has already been used
      if (user.resetTokenUsed) {
        return res.status(400).json({ message: "Reset token already used" });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);

      user.password = hashedPassword;

      // Set reset token flag to true to mark it as used
      user.resetTokenUsed = true;

      await user.save();

      return res.status(200).json({ message: "Password updated successfully" });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  });
  
};
