import nodemailer from "nodemailer";
import fs from 'fs';
import path from "path";
import { fileURLToPath } from "url";
import handlebars from 'handlebars';
import 'dotenv/config'

const __fileName = fileURLToPath(import.meta.url);
const __dirName = path.dirname(__fileName);
const url = process.env.FRONT_URL;

export const verifyEmail = (token, email) => {
  const emailTemplate = fs.readFileSync(
    path.join(__dirName, 'verifyEmail.hbs'), 
    'utf-8'
  );
  const template = handlebars.compile(emailTemplate);
  const htmlToSend = template({ url, token });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAILER_USER,
      pass: process.env.EMAILER_PASSWORD,
    },
  });
  const mailConfigurations = {
    from: process.env.EMAILER_USER,
    to: email,
    subject: "Verify Your Email",
    html: htmlToSend
  };
  transporter.sendMail(mailConfigurations, (error, info) => {
    if (error) {
      console.error("Email send failed:", error);
      return;
    }
    console.log("✅ Verification Email Sent");
  });
};
