import nodemailer from "nodemailer";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import handlebars from "handlebars";

const __fileName = fileURLToPath(import.meta.url);
const __dirName = path.dirname(__fileName);
const url = process.env.FRONT_URL;

export const passwordChangedEmail = (email, name) => {
    const filePath = path.join(__dirName, "passwordChanged.hbs");
    const templateSrc = fs.readFileSync(filePath, "utf-8");
    const template = handlebars.compile(templateSrc);

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
        subject: "✅ Your Password Has Been Changed",
        html: htmlToSend,
    };
    transporter.sendMail(mailOptions, (err) => {
        if (err) {
            console.error("❌ Password change email failed:", err);
            return;
        }
        console.log("✅ Password Change Notification Sent");
    });
};