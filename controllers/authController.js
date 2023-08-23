// controllers/authController.js
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../models/User');
const { jwtSecret } = require('../config');
const mailer = require('../utils/mailer');
require('dotenv').config();

const authController = {
    signup: async (req, res) => {
      try {
        const { email, password } = req.body;
  
        // Check if the email is already registered
        const existingUser = await User.findOne({ email });
        if (existingUser) {
          return res.status(409).json({ message: 'Email already registered' });
        }
  
        // Create a new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
  
        res.status(201).json({ message: 'User registered successfully' });
      } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
      }
    },
    login: async (req, res) => {
        try {
          const { email, password } = req.body;
    
          // Find the user by email
          const user = await User.findOne({ email });
          if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
          }
    
          // Compare hashed passwords
          const passwordMatch = await bcrypt.compare(password, user.password);
          if (!passwordMatch) {
            return res.status(401).json({ message: 'Invalid email or password' });
          }
    
          // Generate and send JWT token
          const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
          res.status(200).json({ token });
        } catch (error) {
          res.status(500).json({ message: 'Internal server error' });
        }
      },
      forgotPassword: async (req, res) => {
        try {
          const { email } = req.body;
    
          // Generate a reset token
          const resetToken = crypto.randomBytes(20).toString('hex');
    
          // Update user's reset token and expiration
          const user = await User.findOneAndUpdate(
            { email },
            { resetToken, resetTokenExpiration: Date.now() + 3600000 }, // Token expires in 1 hour
            { new: true }
          );
    
          if (!user) {
            return res.status(404).json({ message: 'User not found' });
          }
    
          // Send reset link via email
          const resetLink = `http://your-frontend-app/reset-password/${resetToken}`;
          await mailer.sendMail({
            to: user.email,
            subject: 'Password Reset',
            html: `Click <a href="${resetLink}">here</a> to reset your password.`,
          });
    
          res.status(200).json({ message: 'Password reset link sent successfully' });
        } catch (error) {
          res.status(500).json({ message: 'Internal server error' });
        }
      },
      resetPassword: async (req, res) => {
        try {
          const { resetToken, newPassword } = req.body;
    
          // Find user by reset token and ensure token hasn't expired
          const user = await User.findOne({
            resetToken,
            resetTokenExpiration: { $gt: Date.now() },
          });
    
          if (!user) {
            return res.status(400).json({ message: 'Invalid or expired reset token' });
          }
    
          // Update password and reset token
          const hashedPassword = await bcrypt.hash(newPassword, 10);
          user.password = hashedPassword;
          user.resetToken = undefined;
          user.resetTokenExpiration = undefined;
          await user.save();
    
          res.status(200).json({ message: 'Password reset successful' });
        } catch (error) {
          res.status(500).json({ message: 'Internal server error' });
        }
      },





    
  };
  


module.exports = authController;
