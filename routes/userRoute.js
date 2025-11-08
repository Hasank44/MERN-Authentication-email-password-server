import express from 'express';
import {
    userRegisterController, userEmailVerifyController, userEmailReVerifyController,
    userLoginController, userLogoutController, userForgetPassword, userOtpVerify, userSetNewPassword,
    userPasswordChangeController, userReSendOtp
} from '../controllers/userController.js';
import isAuthenticated from '../middlewares/isAuthenticated.js';

const router = express.Router();

// router.get('/', usersGetController);
router.post('/user/register', userRegisterController);
router.post('/user/verify', isAuthenticated, userEmailVerifyController);
router.post('/user/reverify', userEmailReVerifyController);
router.post('/user/login', userLoginController);
router.post('/user/logout', isAuthenticated, userLogoutController);
router.post('/user/password/forget', userForgetPassword);
router.post('/user/re-send/otp/:email', userReSendOtp);
router.post('/user/otp/verify/:email', userOtpVerify);
router.post('/user/change/password/:email', userSetNewPassword);
router.post('/user/password/change', isAuthenticated, userPasswordChangeController);


export default router;