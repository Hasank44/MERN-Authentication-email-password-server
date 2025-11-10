import User from '../models/User.js';
import Session from '../models/Session.js';
import bcrypt from 'bcrypt';
import mongoose from 'mongoose';
import jwt from 'jsonwebtoken';
import validator from 'validator';
import { verifyEmail } from '../utils/verifyEmail.js';
import { sendWelcomeEmail } from '../utils/sendWelcomeEmail.js';
import { sendOtpEmail } from '../utils/sendOtpEmail.js';
import { sendPasswordResetSuccessEmail } from '../utils/sendPasswordResetSuccessEmail.js';
import { passwordChangedEmail } from '../utils/passwordChanged.js';

const secret = process.env.JWT_SECRET;


export const userRegisterController = async (req, res) => {
    try {
        const { userName, email, password } = req.body;
        if (!userName || !email || !password) {
            return res.status(400).json({
                message: 'all fields required'
            });
        };
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                message: 'email not valid'
            });
        };
        const userNames = await User.findOne({ userName });
        if (userNames) {
            return res.status(404).json({
                message: 'user name already in exist'
            });
        };
        const user = await User.findOne({ email });
        if (user) {
            return res.status(404).json({
                message: 'email already in exist'
            });
        };
        const hashedPassword = await bcrypt.hash(password, 11);
        const newUser = new User({
            userName,
            email,
            password: hashedPassword
        });
        const mailerToken = jwt.sign({
            _id: newUser._id
        }, secret, {
            expiresIn: '10m'
        });
        newUser.token = `Bearer ${mailerToken}`;
        await newUser.save();
        verifyEmail(mailerToken, email);
        return res.status(201).json({
            success: true,
            message: 'register success',
            result: newUser
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userEmailVerifyController = async ( req, res ) => {
    try {
        const { _id } = req.user;
        if (!_id) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (!mongoose.Types.ObjectId.isValid(_id)) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        const user = await User.findOne({ _id: _id });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
        };
        if (user.isVerified === true) {
            return res.status(400).json({
                message: 'your account already verified'
            });
        };
        user.token = null;
        user.isVerified = true;
        await user.save();
        let email = user.email;
        let name = user.userName;
        sendWelcomeEmail(email, name);
        return res.status(200).json({
            success: true,
            message: 'email verify success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userEmailReVerifyController = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                message: 'email not valid'
            });
        };
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
        };
        if (user.isVerified === true) {
            return res.status(400).json({
                message: 'your account already verified'
            });
        };
        const newToken = jwt.sign({
            _id: user._id
        }, secret, {
            expiresIn: '10m'
        });
        user.token = newToken;
        await user.save();
        verifyEmail(user.token, user.email);
        return res.status(200).json({
            success: true,
            token: `Bearer ${newToken}`,
            message: 'verification link send success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userLoginController = async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({
                message: 'email & password are required'
            });
        };
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                message: 'invalid email'
            });
        };
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
        };
        const matchPassword = await bcrypt.compare(password, user.password);
        if (!matchPassword) {
            return res.status(400).json({
                message: 'incorrect password'
            });
        };
        if (user.isVerified === false) {
            return res.status(400).json({
                message: 'account not verified'
            });
        };
        user.isLoggedIn = true;
        await user.save();
        const isSession = await Session.findOne({ userId: user._id });
        if (isSession) {
            await Session.deleteMany({ userId: user._id });
        };
        const newSession = new Session({
            userId: user._id
        });
        await newSession.save();
        const accessToken = jwt.sign({
            _id: user._id
        }, secret, {
            expiresIn: '10d'
        });
        const refreshToken = jwt.sign({
            _id: user._id
        }, secret, {
            expiresIn: '10d'
        });
        return res.status(200).json({
            success: true,
            message: 'login success',
            result: user,
            accessToken: `Bearer ${accessToken}`,
            refreshToken: `Bearer ${refreshToken}`
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userLogoutController = async (req, res) => {
    try {
        const { _id } = req.user;
        if (!_id) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (!mongoose.Types.ObjectId.isValid(_id)) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        const user = await User.findOne({ _id: _id });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
        };
        const session = await Session.findOne({ userId: user._id });
        if (session) {
            await Session.deleteMany({ userId: user._id });
        };
        user.isLoggedIn = false;
        await user.save();
        return res.status(200).json({
            success: true,
            message: 'Logout Success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userForgetPassword = async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                message: 'email not valid'
            });
        };
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
        };
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expired = new Date(Date.now() + 10 * 60 * 1000);
        user.otp = otp;
        user.otpExpire = expired;
        await user.save();
        sendOtpEmail(user.email, user.userName, user.otp);
        return res.status(200).json({
            success: true,
            message: 'Otp Sent Success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userReSendOtp = async (req, res) => {
   try {
        const { email } = req.params;
        if (!email) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                message: 'email not valid'
            });
        };
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
       };
       if (user.otp === null) {
           return res.status(400).json({
               message: 'OTP is received'
           });
       };
       if (user.otpExpire === null) {
           return res.status(400).json({
               message: 'OTP is received'
           });
       };
       if (user.otp === false) {
           return res.status(400).json({
               message: 'OTP is received'
           });
       };
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const expired = new Date(Date.now() + 10 * 60 * 1000);
        user.otp = otp;
        user.otpExpire = expired;
        await user.save();
        sendOtpEmail(user.email, user.userName, user.otp);
        return res.status(200).json({
            success: true,
            message: 'Otp re-sent Success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    }; 
};

export const userOtpVerify = async (req, res ) => {
    try {
        const { otp } = req.body;
        const { email } = req.params;
        if (!otp || !email) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                message: 'email not valid'
            });
        };
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
        };
        if (!user.otp || !user.otpExpire) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (user.otpExpire < new Date()) {
            return res.status(400).json({
                message: 'OTP has expired'
            });
        };
        if (otp !== user.otp) {
            return res.status(400).json({
                message: 'invalid OTP'
            });
        };
        user.otp = null;
        user.otpVerified = true;
        const expired = new Date(Date.now() + 10 * 60 * 1000);
        user.otpExpire = expired;
        await user.save();
        return res.status(200).json({
            success: true,
            message: 'OTP verify success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userSetNewPassword = async (req, res) => {
    try {
        const { newPassword, confirmPassword } = req.body;
        const { email } = req.params;
        if (!newPassword || !confirmPassword || !email) {
            return res.status(400).json({
                message: 'all field are required'
            });
        };
        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                message: 'password do not match'
            });
        };
        if (!validator.isEmail(email)) {
            return res.status(400).json({
                message: 'email not valid'
            });
        };
        const hashedPassword = await bcrypt.hash(newPassword, 11);
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                message: 'account not found'
            });
        };
        if (user.otpVerified !== true) {
            return res.status(400).json({
                message: 'Please sent OTP then forget password'
            });
        };
        if (user.otpExpire < new Date()) {
            return res.status(400).json({
                message: 'OTP has expired'
            });
        };
        user.password = hashedPassword;
        user.otpExpire = null;
        user.otpVerified = false;
        await user.save();
        sendPasswordResetSuccessEmail(user.email, user.userName);
        return res.status(200).json({
            success: true,
            message: 'Password reset success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};

export const userPasswordChangeController = async (req, res) => {
    try {
        const { _id } = req.user;
        const { password, newPassword, confirmPassword } = req.body;
        if (!_id) {
            return res.status(400).json({
                message: 'invalid credentials'
            });
        };
        if (!password || !newPassword || !confirmPassword) {
            return res.status(400).json({
                message: 'all fields are required'
            });
        };
        if (newPassword !== confirmPassword) {
            return res.status(400).json({
                message: 'new password do not match'
            });
        };
        if (password === newPassword) {
            return res.status(400).json({
                message: "New password must be different from the old password",
            });
        };
        if (!mongoose.Types.ObjectId.isValid(_id)) {
            return res.status(400).json({
                message: 'invalid user'
            });
        };
        const user = await User.findOne({ _id: _id });
        if (!user) {
            return res.status(400).json({
                message: 'user not found'
            });
        };
        const currentPassword = await bcrypt.compare(password, user.password);
        if (!currentPassword) {
            return res.status(400).json({
                message: 'incorrect password'
            });
        };
        const hashedPassword = await bcrypt.hash(newPassword, 11);
        user.password = hashedPassword;
        await user.save();
        passwordChangedEmail(user.email, user.userName);
        return res.status(200).json({
            success: true,
            message: 'Password Change success'
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: 'Server Error Occurred'
        });
    };
};
