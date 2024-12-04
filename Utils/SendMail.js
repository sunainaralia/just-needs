import dotenv from 'dotenv';
dotenv.config({ path: './config.env' });
import nodemailer from 'nodemailer';
const sendEmail = (option) => {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASSWORD
    }
  });
  const emailOptions = {
    from: {
      name: "Just needs",
      address: process.env.EMAIL_USER
    },
    to: option.email,
    subject: option.subject,
    text: option.msg
  };
  transporter.sendMail(emailOptions);
}



export default sendEmail;