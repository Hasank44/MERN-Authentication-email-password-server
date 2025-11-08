import nodemailer from "nodemailer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import handlebars from "handlebars";

const __fileName = fileURLToPath(import.meta.url);
const __dirName = path.dirname(__fileName);

export const sendOtpEmail = (email, name, otp) => {
  const templatePath = path.join(__dirName, "sendOtpEmail.hbs");
  const templateSource = fs.readFileSync(templatePath, "utf-8");
  const template = handlebars.compile(templateSource);

  const htmlToSend = template({ name, otp });

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
    subject: "Your OTP Code 🔐",
    html: htmlToSend,
  };

  transporter.sendMail(mailOptions, (err) => {
    if (err) {
      console.error("❌ OTP email failed:", err);
      return;
    }
    console.log("✅ OTP Sent Success");
  });
};
