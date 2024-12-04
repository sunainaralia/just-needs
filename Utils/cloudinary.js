import cloudinary from 'cloudinary';
const cloudinaryConfig = cloudinary.v2;
import dotenv from 'dotenv';
dotenv.config({ path: './config.env' });
cloudinaryConfig.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_SECRET_KEY
});

export default cloudinaryConfig;
