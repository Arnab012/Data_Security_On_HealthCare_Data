const mongoose = require("mongoose");

const patientSchema = new mongoose.Schema({
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
  dob: {
    type: String, // Change type to String
    required: [true, "Date of Birth is required."],
  },
  gender: {
    type: String,
    required: [true, "Gender is required."],
  },
  address: {
    state: {
      type: String,
    },
    city: {
      type: String,
    },
    vill_or_town: {
      type: String,
    },
  },
  ph: {
    type: String,
    unique: true,
  },

  email: {
    type: String,
    unique: true,
  },

  password: {
    type: String,
    required: [true, "Password is required."],
  },

  department: {
    type: String,
  },
  encryptedCustomId: {
    type: String,
  },
});

const Patient = mongoose.model("Patient", patientSchema);

module.exports = Patient;
