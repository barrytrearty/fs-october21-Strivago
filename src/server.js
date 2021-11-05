import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import passport from "passport";
import cookieParser from "cookie-parser";
import GoogleStrategy from "./auth/oauth.js";
import listEndpoints from "express-list-endpoints";
import usersRouter from "./users/index.js";
import accomodationRouter from "./accomodation/index.js";

const server = express();
const port = process.env.PORT || 3001;

passport.use("google", GoogleStrategy);

server.use(cors({ origin: "http://localhost:3000", credentials: true }));
server.use(express.json());
server.use(passport.initialize());
server.use(cookieParser());

server.use("/users", usersRouter);
server.use("/accomodation", accomodationRouter);

console.table(listEndpoints(server));

mongoose.connect(process.env.MONGO_CONNECTION);

mongoose.connection.on("connected", () => {
  console.log("Mongo connected!");
  server.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
});
