import nodemailer from "nodemailer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import handlebars from "handlebars";

const __fileName = fileURLToPath(import.meta.url);
const __dirName = path.dirname(__fileName);
const urls = process.env.FRONT_URL;
const url = `${urls}/api/v1/users/user/password/forget`

export const sendPasswordResetSuccessEmail = (email, name) => {
  const templatePath = path.join(__dirName, "passwordReseted.hbs");
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
    subject: "✅ Your Password Has Been Reset",
    html: htmlToSend,
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      console.error("❌ Password reset success email failed:", err);
      return;
    }
    console.log("✅ Password Reset Success Email Sent");
  });
};
