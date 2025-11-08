import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import mongoose from 'mongoose';
const SECRET = process.env.JWT_SECRET;

const isAuthenticated = async (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      message: 'Authorization header missing or invalid'
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    if (!mongoose.Types.ObjectId.isValid(decoded._id)) {
      return res.status(500).json({
        success: false,
        message: 'Invalid Credentials'
      });
    };
    const user = await User.findOne({ _id: decoded._id });
    if (!user) {
      return res.status(400).json({
        success: false,
        message: 'User Not Found'
      });
    };
    if (decoded._id === !user._id) {
      return res.status(500).json({
        success: false,
        message: 'Invalid Credentials'
      });
    };
    req.user = user;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

export default isAuthenticated;
