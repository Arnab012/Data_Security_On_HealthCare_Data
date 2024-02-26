const mongoose = require("mongoose");

const nurseSchema = new mongoose.Schema({
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
  },
  password: {
    type: String,
    required: [true, "Password is required."],
  },
  ph: {
    type: String,
  },
  dob: {
    type: String,
    required: [true, "Date of Birth is required."],
  },
  gender: {
    type: String,
    required: [true, "Gender is required."],
  },
  address: {
    state: {
      type: String,
      required: [true, "State is required."],
    },
    city: {
      type: String,
      required: [true, "City is required."],
    },
  },

  role: {
    type: String,
  },
  department: {
    type: String,
    required: [true, "Department is required."],
  },
  limit: {
    type: Number,
    default: 0,
  },
  encryptedCustomId: {
    type: String,
  },
});

const Nurse = mongoose.model("Nurse", nurseSchema);

module.exports = Nurse;
