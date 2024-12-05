import { Router } from "express";
import { signUpUser, LoginUser, getUserProfile, editUser, changePassword, forgotPassword, verifyOtp, setNewPassword } from "../Controllers/UserController.js";
import VerifyToken from '../Middlewares/VerifyToken.js'

export const userRouter = Router();
userRouter.route('/')
  .post(signUpUser)
  .get(VerifyToken, getUserProfile)
  .patch(VerifyToken, editUser)
userRouter.route('/change-password/')
  .patch(VerifyToken, changePassword)
userRouter.route('/login/')
  .post(LoginUser)
userRouter.route('/forgot-password/')
  .post(forgotPassword)
userRouter.route('/verify-otp/')
  .patch(verifyOtp)
userRouter.route('/set-password/:userId')
  .patch(setNewPassword)
