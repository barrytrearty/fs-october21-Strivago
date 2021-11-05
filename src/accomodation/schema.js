import mongoose from "mongoose";
import bcrypt from "bcrypt";

const { Schema, model } = mongoose;

const AccomodationSchema = new Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  maxGuests: { type: Number, required: true },
  city: { type: String, required: true },
  host: [{ type: Schema.Types.ObjectId, ref: "users" }],
});

// AccomodationSchema.pre("save", async function (next) {
//   const newAccomodation = this;
//   const plainPW = newAccomodation.password;

//   if (newAccomodation.isModified("password")) {
//     newAccomodation.password = await bcrypt.hash(plainPW, 10);
//   }
//   next();
// });

export default model("accomodation", AccomodationSchema);
