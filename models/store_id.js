const mongoose = require("mongoose");

const encryptedIdSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  encryptedId: {
    type: String,
    required: true,
  },
});

const EncryptedId = mongoose.model("EncryptedId", encryptedIdSchema);

module.exports = EncryptedId;
