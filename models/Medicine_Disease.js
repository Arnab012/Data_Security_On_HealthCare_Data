const mongoose = require("mongoose");

const patientMedicineDiseaseSchema = new mongoose.Schema({
  super_encryptedCustomId: {
    type: String,
    required: true,
  },
  DiseaseDetails: {
    type: [String],
    required: false,
  },
  NameOfMedicine: {
    type: String,
    required: false,
  },
  Description: {
    type: String,
    required: false,
  },
  UsageInstructions: {
    type: String,
    required: false,
  },
});

// Export the schema
module.exports = mongoose.model(
  "PatientMedicineDiseaseReport",
  patientMedicineDiseaseSchema
);
