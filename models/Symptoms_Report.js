const mongoose = require("mongoose");

const patientSymptomPathologySchema = new mongoose.Schema({

  second_encryptedCustomId: {
    type: String,
    required: false,
  },
  symptoms: {
    type: String,
    required: false,
  },
  dateOfSymptom: {
    type: Date,
    default: Date.now,
  },
  reportText: {
    type: String,
    required: false,
  },
  dateOfReport: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model(
  "PatientSymptomPathologyReport",
  patientSymptomPathologySchema
);
