import nodemailer from "nodemailer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import handlebars from "handlebars";

const __fileName = fileURLToPath(import.meta.url);
const __dirName = path.dirname(__fileName);
const url = process.env.FRONT_URL;

export const sendWelcomeEmail = (email, name) => {
  
  const templatePath = path.join(__dirName, "welcome.hbs");
  const templateSource = fs.readFileSync(templatePath, "utf-8");
  const template = handlebars.compile(templateSource);

  const htmlToSend = template({ url, name });

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAILER_USER,
      pass: process.env.EMAILER_PASSWORD,
    },
  });

  const mailOptions = {
    from: process.env.EMAILER_USER,
    to: email,
    subject: "Welcome! 🎉 Your Account is Verified",
    html: htmlToSend,
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error("❌ Welcome email failed:", error);
      return;
    }
    console.log("✅ Welcome Email Sent");
  });
};
