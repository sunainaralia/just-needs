import CustomErrorHandler from "../Utils/CustomErrorHandler.js";
import asyncFunHandler from "../Utils/asyncFunHandler.js";
import { promisify } from "util";
import User from "../Models/UserModel.js";
import pkg from "jsonwebtoken";
const { verify } = pkg;
// verify token
const verifyToken = asyncFunHandler(async (req, res, next) => {
  // check if token is provided or not
  let testToken = req.headers.authorization
  let token;
  if ((testToken) && (testToken.startsWith('Bearer'))) {
    token = testToken.split(' ')[1];
  }
  if (!token) {
    return next(new CustomErrorHandler("token is not provided or login is required", 401));
  };
  // check if the token is valid
  const decodedToken = await promisify(verify)(token, process.env.SECRET_KEY)
  // check if user exists or not
  const users = await User.findById(decodedToken.id)
  if (!users) {
    return next(new CustomErrorHandler("this token is not verified means no user is found", 401))
  }
  req.user = users
  next();
});
export default verifyToken;