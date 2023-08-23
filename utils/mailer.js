// utils/mailer.js
const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.JWT_EMAIL,
    pass: process.env.JWT_PASSWORD,
  },
});

module.exports = transporter;
