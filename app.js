import express from "express";
import cors from "cors";
import CustomErrorHandler from "./Utils/CustomErrorHandler.js";
import ErrorHandling from "./Controllers/ErrorHandling.js";
import { userRouter } from './Routes/UserRouter.js';
const app = express();

// Enable CORS
app.use(cors({
  origin: "*",
  methods: "GET,POST,PUT,PATCH,DELETE",
  allowedHeaders: "Content-Type,Authorization",
}));

app.use(express.json());

// Routes for user
app.use('/api/v1/user/', userRouter);
app.all("*", (req, res, next) => {
  let err = new CustomErrorHandler(`The given URL ${req.originalUrl} is not present`, 400);
  next(err);
});

// Error handling middleware
app.use(ErrorHandling);

export default app;
