const mongoose = require("mongoose");

const doctorSchema = new mongoose.Schema({
  customId: {
    type: String,
    default: function () {
      return "custom_" + Date.now();
    },
    unique: true,
  },
  name: {
    type: String,
    required: [true, "Name is required."],
  },
  email: {
    type: String,
    required: [true, "Email is required."],
    unique: true,
  },
  password: {
    type: String,
    required: [true, "Password is required."],
  },
  ph: {
    type: String,
    unique: true,
  },
  dob: {
    type: String,
    required: [true, "Date of Birth is required."],
  },
  gender: {
    type: String,
  },
  address: {
    state: {
      type: String,
    },
    city: {
      type: String,
    },
  },
  registration: {
    type: String,
  },
  role: {
    type: String,
    required: true,
  },
  department: {
    type: String,
    required: [true, "Specialization is required."],
  },
  limit: {
    type: Number,
    default: 0,
  },
  encryptedCustomId: {
    type: String,
  },
});

const Doctor = mongoose.model("Doctor", doctorSchema);

module.exports = Doctor;
