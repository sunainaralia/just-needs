import User from '../Models/UserModel.js';
import pkg from 'jsonwebtoken';
import CustomErrorHandler from '../Utils/CustomErrorHandler.js';
import asyncFunHandler from '../Utils/asyncFunHandler.js';
import sendEmail from '../Utils/SendMail.js';
import crypto from 'crypto';
const { sign } = pkg;
import bcryptjs from 'bcryptjs';
///////////////////// genrate token ////////////////
const genrateToken = (id) => {
  return sign({ id }, process.env.SECRET_KEY, {
    expiresIn: process.env.EXPIRED_TIME
  })
};

// Sign up API for Users (Email Optional)
export const signUpUser = asyncFunHandler(async (req, res, next) => {
  const { name, email, phone_no, password, role } = req.body;

  // Check for existing email if provided
  if (email) {
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(new CustomErrorHandler("Email is already registered.", 409));
    }
  }

  // Create new user
  const newUser = await User.create({ name, email, phone_no, password, role });

  // Generate token
  const token = genrateToken(newUser._id);

  // Send response
  res.status(201).json({
    success: true,
    message: "User registered successfully.",
    user: {
      id: newUser._id,
      name: newUser.name,
      email: newUser.email || null,
      phone_no: newUser.phone_no,
      role: newUser.role,
    },
    token,
  });
});

//////////////////////// login the client/////////////////////
export const LoginUser = asyncFunHandler(async (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  if (!email || !password) {
    let err = new CustomErrorHandler("email or password is not provided", 400)
    return next(err);
  }
  const user = await User.findOne({ email })
  if (!user || !(await user.comparePasswordInDb(password, user.password))) {
    let err = new CustomErrorHandler("email or password is not correct", 400)
    return next(err);
  }
  let token = genrateToken(user._id)
  res.status(200).json({
    success: true,
    msg: "user is login successfully",
    data: user,
    token
  })
})

////////////////////////// get client profile //////////////////
export const getUserProfile = asyncFunHandler(async (req, res, next) => {
  const user = req.user;

  if (!user) {
    return next(new CustomErrorHandler("User not found", 404));
  }

  let profileData;

  // Check the user's role and fetch data from the relevant schema
  if (user.role === 'client') {
    profileData = await Client.findOne({ userId: user._id });
  } else if (user.role === 'driver') {
    profileData = await Driver.findOne({ userId: user._id });
  }

  // Combine user data with profile data, if available
  let fullProfile;
  if (profileData) {
    fullProfile = {
      ...user.toObject(),
      ...profileData.toObject() || {} // Spread profile data if it exists
    };
  } else {
    fullProfile = {
      ...user.toObject()
    };
  }

  res.status(200).json({
    success: true,
    msg: "User profile fetched successfully",
    data: fullProfile
  });
});

//////////////// update the client profile //////////////////
export const editUser = asyncFunHandler(async (req, res) => {
  let role = req.user.role
  const { name, email, phone_no, password, confirmPassword, zone_assigned, status, businessName, province, city, postalCode, address1, license, license_image, availability, address, address2 } = req.body;
  const getUserndUpdate = await User.findByIdAndUpdate(req.user.id, { name, email, phone_no, password, role, confirmPassword, zone_assigned, status }, { new: true, runValidators: true });
  // Update role-specific data in the appropriate model
  let roleData;
  if (role === 'client') {
    roleData = await Client.findOneAndUpdate(
      { userId: req.user.id },
      { businessName, province, city, postalCode, address1, address2 },
      { new: true, runValidators: true }
    );
  } else if (role === 'driver') {
    roleData = await Driver.findOneAndUpdate(
      { userId: req.user.id },
      { license, license_image, address, availability },
      { new: true, runValidators: true }
    );
  }

  let responseData;
  if (roleData) {
    responseData = {
      ...getUserndUpdate.toObject(),
      ...(roleData?.toObject() || {})
    };
  } else {
    responseData = {
      ...getUserndUpdate.toObject()
    };
  }
  res.status(200).json({
    success: true,
    msg: "user is updated succesfully",
    data: responseData
  })
});


////////////////// change password//////////////////////
export const changePassword = asyncFunHandler(async (req, res, next) => {
  let user = await User.findById(req.user._id)
  let savedPassword = user.password;
  let currentPassword = req.body.currentPassword
  if (!currentPassword) {
    const err = new CustomErrorHandler("plz provide current password", 404);
    return next(err);
  }
  let comparepassword = await user.comparePasswordInDb(req.body.currentPassword, savedPassword);
  if (!comparepassword) {
    let err = new CustomErrorHandler("old password is not correct", 403);
    return next(err)
  }
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  await user.save();
  let token = genrateToken(user._id);
  res.status(200).json({
    success: true,
    msg: "password is changed successfully",
    token: token
  })
});

///////////////// forgot password ///////////////////////
export const forgotPassword = asyncFunHandler(async (req, res, next) => {
  const email = req.body.email;
  if (!email) {
    const err = new CustomErrorHandler("plz provide the email ", 404);
    next(err);
  }
  const user = await User.findOne({ email })
  if (!user) {
    const err = new CustomErrorHandler("plz provide the valid email this is not registered", 404);
    next(err);
  }

  const resetToken = await user.resetPasswordToken();
  await user.save({ validateBeforeSave: false });
  console.log(user.otpExpiresIn)
  const msg = `otp for change password ${resetToken} and this is valid upto ${user.otpExpiresIn} ,please verify this `
  try {
    sendEmail({
      msg: msg,
      email: user.email,
      subject: "email for reset password"
    })
    return res.status(200).json({
      success: true,
      msg: "email is sent to your registered mail"
    })
  } catch (err) {
    user.otp = undefined;
    user.otpExpiresIn = undefined;
    await user.save({ validateBeforeSave: false });
    const errors = new CustomErrorHandler("some error has occured during sending the email", 500)
    return next(errors);
  }
});


///////////////// reset password////////////////////////
export const verifyOtp = asyncFunHandler(async (req, res, next) => {
  const { otp } = req.body;

  // Check if OTP is provided
  if (!otp) {
    return next(new CustomErrorHandler("Please provide an OTP", 403));
  }

  // Find the user with the matching OTP and check if it hasn't expired
  const user = await User.findOne({ otp, otpExpiresIn: { $gt: Date.now() } });

  if (!user) {
    return next(new CustomErrorHandler("Invalid or expired OTP", 403));
  }

  // If OTP is valid, clear OTP fields to prevent reuse
  user.otp = undefined;
  user.otpExpiresIn = undefined;
  await user.save();

  // Send the user's ID in the response for the next step
  return res.status(200).json({
    success: true,
    msg: "OTP verified successfully",
    userId: user._id
  });
});
export const setNewPassword = asyncFunHandler(async (req, res, next) => {
  const { userId } = req.params;
  const { password, confirmPassword } = req.body;

  // Check if passwords match
  if (password !== confirmPassword) {
    return next(new CustomErrorHandler("Passwords do not match", 400));
  }

  // Find the user by ID
  const user = await User.findById(userId);
  if (!user) {
    return next(new CustomErrorHandler("User not found", 404));
  }

  // Update the user's password
  user.password = password;
  user.confirmPassword = confirmPassword;
  await user.save();

  // Generate a new token for the user
  const loginToken = genrateToken(user._id);

  return res.status(200).json({
    success: true,
    msg: "Password changed successfully",
    token: loginToken
  });
});



////////////////////////////// find client,admin,driver by id////////////////////////

export const getUserProfileById = asyncFunHandler(async (req, res, next) => {
  const user = await User.findById(req.params.id);
  if (!user) {
    return next(new CustomErrorHandler("User not found", 404));
  }

  let profileData;

  // Check the user's role and fetch data from the relevant schema
  if (user.role === 'client') {
    profileData = await Client.findOne({ userId: user._id });
  } else if (user.role === 'driver') {
    profileData = await Driver.findOne({ userId: user._id });
  }

  // Combine user data with profile data, if available
  let fullProfile;
  if (profileData) {
    fullProfile = {
      ...user.toObject(),
      ...profileData.toObject() || {} // Spread profile data if it exists
    };
  } else {
    fullProfile = {
      ...user.toObject()
    };
  }
  res.status(200).json({
    success: true,
    msg: "User profile fetched successfully",
    data: fullProfile
  });
});

////////////////////////////// edit client,admin,driver by id////////////////////////
export const editUserById = asyncFunHandler(async (req, res) => {
  let user = await User.findById(req.params.id)
  if (!user) {
    return next(new CustomErrorHandler("User not found", 404));
  };
  let role = user.role
  const { name, email, phone_no, password, confirmPassword, zone_assigned, status, businessName, province, city, postalCode, address1, license, license_image, availability, address, address2 } = req.body;
  const getUserndUpdate = await User.findByIdAndUpdate(user.id, { name, email, phone_no, password, role, confirmPassword, zone_assigned, status }, { new: true, runValidators: true });
  // Update role-specific data in the appropriate model
  let roleData;
  if (role === 'client') {
    roleData = await Client.findOneAndUpdate(
      { userId: user.id },
      { businessName, province, city, postalCode, address1, address2 },
      { new: true, runValidators: true }
    );
  } else if (role === 'driver') {
    roleData = await Driver.findOneAndUpdate(
      { userId: user.id },
      { license, license_image, address, availability },
      { new: true, runValidators: true }
    );
  }

  let responseData;
  if (roleData) {
    responseData = {
      ...getUserndUpdate.toObject(),
      ...(roleData?.toObject() || {})
    };
  } else {
    responseData = {
      ...getUserndUpdate.toObject()
    };
  }
  res.status(200).json({
    success: true,
    msg: "user is updated succesfully",
    data: responseData
  })
});


////////////////////////////// delete client,admin,driver by id////////////////////////
export const deleteUserById = asyncFunHandler(async (req, res, next) => {
  let user = await User.findById(req.params.id);

  // Check if user exists
  if (!user) {
    return next(new CustomErrorHandler("No user found", 404)); // Return the error
  }

  let role = user.role;

  // Handle role-specific deletions
  if (role === "client") {
    await Customer.findOneAndDelete({ customerOf: user.id });
    await Client.findOneAndDelete({ userId: user.id });
  } else if (role === "driver") {
    await Driver.findOneAndDelete({ userId: user.id });
  }
  await User.findByIdAndDelete(req.params.id);
  res.status(200).json({
    success: true,
    msg: `${role} is deleted successfully`
  });
});
