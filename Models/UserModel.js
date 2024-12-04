import mongoose from 'mongoose';
import validator from 'validator';
import bcryptjs from 'bcryptjs';
// all user schema or admin schema 
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Name is required"]
  },
  email: {
    type: String,
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, "Please enter a valid email"]
  },
  phone_no: {
    type: String,
    required: [true, "Phone number is required"],
    validate: {
      validator: function (v) {
        return /^[0-9]{10}$/.test(v);
      },
      message: "Please enter a valid 10-digit phone number"
    },
    unique:[true]
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minLength: 5
  },
  role: {
    type: String,
    required: true
  },
  status: {
    type: Boolean,
    default: true
  },
  otp:Number,
  otpExpiresIn: Date,
}, {
  timestamps: { createdAt: 'created_at', updatedAt: 'updated_at' }
});



userSchema.pre('save', async function (next) {
  // Hash password if modified
  if (this.isModified('password')) {
    this.password = await bcryptjs.hash(this.password, 12);
  }
  next();
});

// method to compare the password
userSchema.methods.comparePasswordInDb = async function (pass, passInDb) {
  return await bcryptjs.compare(pass, passInDb);

}
userSchema.methods.resetPasswordToken = async function () {
  const otp = Math.floor(1000 + Math.random() * 9000);
  this.otp = otp;
  this.otpExpiresIn = Date.now() + 10 * 60 * 1000;
  return otp;
}

// export all users (admin,client,user)
const User = mongoose.model('User', userSchema);
export default User;

