import dotenv from "dotenv";
dotenv.config({ path: './config.env' });
import app from "./app.js";
import mongoose from "mongoose";
// connect to the database
mongoose.connect(process.env.CONN_STR).then((conn) => {
  console.log("mongodb is connected successfully");
});
// uncaught exception
// process.on('uncaughtException', (err) => {
//   console.log(err.name, err.msg);
//   console.log("unhandled error rejection ,server is shutting down !!!");
//   process.exit(1);
// })
// listen the server

const server = app.listen(process.env.PORT, () => {
  console.log("server is running successfully");
});
// unhandled rejection
// process.on('unhandledRejection', (err) => {
//   console.log(err.name, err.msg);
//   console.log("unhandled error rejection ,server is shutting downs !!!");
//   server.close(() => { process.exit(1) })
// })

