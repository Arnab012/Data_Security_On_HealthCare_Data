const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/gen_info");
const Doctor = require("../models/Doctor");
const Nurse = require("../models/Nurse");
const crypto = require("crypto");
const Medicine_Disease = require("../models/Medicine_Disease");
const EncryptedId = require("../models/store_id");
const symtpreport = require("../models/Symptoms_Report");
const Symptoms_Report = require("../models/Symptoms_Report");

// Function to encrypt the customId
const encryptCustomId = (customId) => {
  const algorithm = "aes-256-cbc";
  const key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const iv = "aaddjjddjjddjjdd";
  const cipher = crypto.createCipheriv(algorithm, key, iv);
  let encrypted = cipher.update(customId, "utf-8", "hex");
  encrypted += cipher.final("hex");
  return `${encrypted}:${iv.toString("hex")}:${key.toString("hex")}`;
};

// Function to decrypt the encryptedCustomId
const decryptCustomId = (encryptedCustomId) => {
  const [encrypted, iv, key] = encryptedCustomId.split(":");

  const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

  let decrypted = decipher.update(encrypted, "hex", "utf-8");
  decrypted += decipher.final("utf-8");
  return decrypted;
};

exports.submitdata = async (req, res, next) => {
  try {
    const { name, email, ph, address, dob, gender, password, department } =
      req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptedemail = encryptCustomId(email);
    const existingUser = await User.findOne({ email: encryptedemail });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "A user with this email already exists.",
      });
    }

    // Encrypt sensitive fields before saving
    if (address && address.state) {
      address.state = encryptCustomId(address.state.toString());
    }
    if (address && address.city) {
      address.city = encryptCustomId(address.city.toString());
    }
    if (address && address.vill_or_town) {
      address.vill_or_town = encryptCustomId(address.vill_or_town.toString());
    }
    const encryptedDept = encryptCustomId(department);

    // Find doctors and nurses with limit less than or equal to 10
    const doctors = await Doctor.find({
      department: encryptedDept,
      limit: { $lte: 10 },
    });
    const nurses = await Nurse.find({
      department: encryptedDept,
      limit: { $lte: 10 },
    });

    // Find the doctor and nurse with the minimum limit
    const minDoctor =
      doctors.length > 0
        ? doctors.reduce((min, doctor) =>
            doctor.limit < min.limit ? doctor : min
          )
        : null;

    const minNurse =
      nurses.length > 0
        ? nurses.reduce((min, nurse) => (nurse.limit < min.limit ? nurse : min))
        : null;

    // Increase the limit of the doctor and nurse by 1
    if (minDoctor) {
      minDoctor.limit += 1;
      await minDoctor.save();
    }
    if (minNurse) {
      minNurse.limit += 1;
      await minNurse.save();
    }

    // Combine the customIds and encrypt
    const customId = `${minDoctor ? minDoctor.customId : ""}_${
      minNurse ? minNurse.customId : ""
    }`;
    const encryptedCustomId = encryptCustomId(customId);
    const encryptedName = encryptCustomId(name);
    const encryptedEmail = encryptCustomId(email);
    const encryptedGender = encryptCustomId(gender);
    const encryptedDOB = encryptCustomId(dob);
    const encryptedPH = encryptCustomId(ph);

    const encryptedId = new EncryptedId({
      name: encryptedName,
      email: encryptedEmail,
      encryptedId: encryptedCustomId,
    });
    const second_encryptedCustomId = new symtpreport({
      second_encryptedCustomId: crypto
        .createHash("sha512")
        .update(encryptedCustomId)
        .digest("hex"),
    });

    const super_encryptedCustomId = new Medicine_Disease({
      super_encryptedCustomId: crypto
        .createHash("sha256")
        .update(encryptedCustomId)
        .digest("hex"),
    });

    await encryptedId.save();
    await super_encryptedCustomId.save();
    await second_encryptedCustomId.save();

    const user = new User({
      name: encryptedName,
      email: encryptedEmail,
      ph: encryptedPH,
      address,
      dob: encryptedDOB,
      gender: encryptedGender,
      password: hashedPassword,
      department: encryptedDept,
      encryptedCustomId,
    });

    await user.validate();
    await user.save();

    res.status(201).json({
      success: true,
      user,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
// login route
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const encryptedEmail = encryptCustomId(email);

    const user = await User.findOne({ email: encryptedEmail });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    // Decrypting nested fields
    const decryptedAddress = {
      state: decryptCustomId(user.address.state),
      city: decryptCustomId(user.address.city),
      vill_or_town: decryptCustomId(user.address.vill_or_town),
    };

    const decryptedUser = {
      ...user.toObject(),
      address: decryptedAddress,
      name: decryptCustomId(user.name),
      dob: decryptCustomId(user.dob),
      gender: decryptCustomId(user.gender),
      ph: decryptCustomId(user.ph),
      email: decryptCustomId(user.email),
      department: decryptCustomId(user.department),
      customId: user.customId,
      encryptCustomId: decryptCustomId(user.encryptedCustomId),
    };

    // Ensure that 'password' is not undefined or null
    if (!password) {
      return res.status(400).json({
        success: false,
        message: "Password is required.",
      });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: "Invalid password.",
      });
    }

    const token = jwt.sign({ userId: user._id }, "your-secret-key", {
      expiresIn: "15d",
    });
    res.cookie("token", token, { httpOnly: true });

    res.status(200).json({
      success: true,
      token,
      user: decryptedUser,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
exports.logout = async (req, res, next) => {
  try {
    // Invalidate the token by setting it to null
    const token = null; // Set the token to null or revoke it on the server side

    res.status(200).json({
      success: true,
      message: "Logout successful.",
      user: null, // Optionally send back user as null
      token: null, // Set the token to null in the response
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

exports.getProfile = async (req, res, next) => {
  try {
    // Check if req.user is defined
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }
    // Assuming User model is imported and findById method is available
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }
    const decryptedAddress = {
      state: decryptCustomId(user.address.state),
      city: decryptCustomId(user.address.city),
      vill_or_town: decryptCustomId(user.address.vill_or_town),
    };

    const decryptedUser = {
      ...user.toObject(),
      address: decryptedAddress,
      name: decryptCustomId(user.name),
      dob: decryptCustomId(user.dob),
      gender: decryptCustomId(user.gender),
      ph: decryptCustomId(user.ph),
      email: decryptCustomId(user.email),
      department: decryptCustomId(user.department),
      customId: user.customId,
      encryptCustomId: decryptCustomId(user.encryptedCustomId),
    };

    res.status(200).json({
      success: true,
      message: "User Fetch Successfully",
      user: decryptedUser,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Patinet Acessing his own medicine and asysmptoms report
exports.medicinenad_report_collection = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    const user = await User.findById(req.user._id);

    const super_encryptedCustom = user.encryptedCustomId;

    const hashedSuperEncryptedCustom = crypto
      .createHash("sha256")
      .update(super_encryptedCustom)
      .digest("hex");

    // Assuming Medicine_Disease is a Mongoose model
    const medicinetabeldata = await Medicine_Disease.find({
      super_encryptedCustomId: hashedSuperEncryptedCustom,
    });

    if (!medicinetabeldata || !medicinetabeldata.length) {
      // Check if data exists
      return res.status(404).json({
        success: false,
        message: "No medicine table data found for the user",
      });
    }
    const DesiesDetail = medicinetabeldata[0].DiseaseDetails[0];
    const NameofMedicine = medicinetabeldata[0].NameOfMedicine;
    const Description = medicinetabeldata[0].Description;
    const UsageInstructions = medicinetabeldata[0].UsageInstructions;
    const decryptedDesiesDetail = decryptCustomId(DesiesDetail);
    const decryptedDescription = decryptCustomId(Description);
    const decryptedNameOfMedicine = decryptCustomId(NameofMedicine);
    const decryptedUsageInstruction = decryptCustomId(UsageInstructions);

    // Decrypt each document in the array
    const decryptmedicaldata = {
      DiseaseDetails: decryptedDesiesDetail,

      NameOfMedicine: decryptedNameOfMedicine,
      Description: decryptedDescription,
      UsageInstructions: decryptedUsageInstruction,
    };

    res.status(200).json({
      success: true,
      message: "User medicine table data fetched successfully",
      medicinetabeldata: decryptmedicaldata,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Patinet Acessing his own symptoms and report
exports.symptoms_report_collection = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    const user = await User.findById(req.user._id);

    const second_encryptedCustom = user.encryptedCustomId;

    const hashedSuperEncryptedCustom = crypto
      .createHash("sha512")
      .update(second_encryptedCustom)
      .digest("hex");

    // Assuming Medicine_Disease is a Mongoose model
    const symptamd_reportdata = await Symptoms_Report.find({
      second_encryptedCustomId: hashedSuperEncryptedCustom,
    });

    if (!symptamd_reportdata || !symptamd_reportdata.length) {
      // Check if data exists
      return res.status(404).json({
        success: false,
        message: "No symptoms and reporit table data found for the user",
      });
    }

    const symtpreportext = symptamd_reportdata[0].reportText;
    const symptom = symptamd_reportdata[0].symptoms;
    const decryptedsymptomreport = decryptCustomId(symtpreportext);
    const decryptedsymptom = decryptCustomId(symptom);

    const decryptedreports = {
      reportText: decryptedsymptomreport,
      symptom: decryptedsymptom,
    };

    res.status(200).json({
      success: true,
      message: "Symptoms table data fetched successfully",
      symptamd_reportdata: decryptedreports,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
///updatedUser try to update his profile of general information
exports.updateProfile = async (req, res, next) => {
  try {
    // Check if req.user is defined
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    // Assuming User model is imported and findByIdAndUpdate method is available
    const updatedUser = await User.findByIdAndUpdate(req.user._id, req.body, {
      new: true,
    });

    if (!updatedUser) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }
    // Update all fields without decrypting
    if (req.body.name) {
      updatedUser.name = encryptCustomId(req.body.name);
    }
    if (req.body.dob) {
      updatedUser.dob = encryptCustomId(req.body.dob);
    }
    if (req.body.gender) {
      updatedUser.gender = encryptCustomId(req.body.gender);
    }
    if (req.body.address && req.body.address.state) {
      updatedUser.address.state = encryptCustomId(req.body.address.state);
    }
    if (req.body.address && req.body.address.city) {
      updatedUser.address.city = encryptCustomId(req.body.address.city);
    }
    if (req.body.address && req.body.address.vill_or_town) {
      updatedUser.address.vill_or_town = encryptCustomId(
        req.body.address.vill_or_town
      );
    }
    if (req.body.ph) {
      updatedUser.ph = encryptCustomId(req.body.ph);
    }
    if (req.body.email) {
      updatedUser.email = encryptCustomId(req.body.email);
    }
    if (req.body.password) {
      // If you want to update the password, hash it before storing
      updatedUser.password = await bcrypt.hash(req.body.password, 10);
    }
    if (req.body.department) {
      updatedUser.department = encryptCustomId(req.body.department);
    }
    if (req.body.registration) {
      updatedUser.registration = encryptCustomId(req.body.registration);
    }
    if (req.body.role) {
      updatedUser.role = encryptCustomId(req.body.role);
    }
    // Save the updated updatedUser
    const Userupdated = await updatedUser.save();
    res.status(200).json({
      success: true,
      message: "User updated successfully",
      user: Userupdated,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
// update medicine tabel by the patient
exports.updatemedicinetabel = async (req, res, next) => {
  try {
    // Check if req.user is defined
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    // Assuming User model is imported and findById method is available
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Extract encryptedCustomId from the user
    const super_encryptedCustom = user.encryptedCustomId;

    // Hash the encryptedCustomId
    const hashedSuperEncryptedCustom = crypto
      .createHash("sha256")
      .update(super_encryptedCustom)
      .digest("hex");

    // Assuming Medicine_Disease model is imported
    let updateData = req.body;

    // Check if values exist and encrypt them
    if (req.body.DiseaseDetails) {
      updateData.DiseaseDetails = encryptCustomId(
        req.body.DiseaseDetails.toString()
      );
    }
    if (req.body.NameOfMedicine) {
      updateData.NameOfMedicine = encryptCustomId(
        req.body.NameOfMedicine.toString()
      );
    }
    if (req.body.Description) {
      updateData.Description = encryptCustomId(req.body.Description.toString());
    }
    if (req.body.UsageInstructions) {
      updateData.UsageInstructions = encryptCustomId(
        req.body.UsageInstructions.toString()
      );
    }

    // Update the medicinetabeldata
    const medicinetabeldata = await Medicine_Disease.findOneAndUpdate(
      {
        super_encryptedCustomId: hashedSuperEncryptedCustom,
      },
      updateData,
      {
        new: true,
      }
    );

    // Return the updated medicine data
    res.status(200).json({
      success: true,
      message: "Medicine data updated successfully",
      medicinetabelUpdate_Data: medicinetabeldata,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// patient update his sympttable and report tabel
exports.updatesymptomsandreport = async (req, res, next) => {
  try {
    // Check if req.user is defined
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    // Assuming User model is imported and findById method is available
    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // Extract encryptedCustomId from the user
    const second_encryptedCustomId = user.encryptedCustomId;

    // Hash the encryptedCustomId
    const hashedSecondEncryptedCustom = crypto
      .createHash("sha512")
      .update(second_encryptedCustomId)
      .digest("hex");

    // Assuming PatientSymptomPathologyReport model is imported
    let updateData = {
      symptoms: req.body.symptoms,
      reportText: req.body.reportText,
    };

    // Check if values exist and encrypt them
    if (req.body.symptoms) {
      updateData.symptoms = encryptCustomId(req.body.symptoms.toString());
    }
    if (req.body.reportText) {
      updateData.reportText = encryptCustomId(req.body.reportText.toString());
    }

    // Update the reporttabeldata
    const reporttabeldata = await symtpreport.findOneAndUpdate(
      {
        second_encryptedCustomId: hashedSecondEncryptedCustom,
      },
      updateData,
      {
        new: true,
      }
    );

    // Return the updated report data
    res.status(200).json({
      success: true,
      message: "Report data updated successfully",
      reporttabeldata: reporttabeldata,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

// Patient can delete his entire 3 collection  own profile
exports.deleteProfile = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    const user = await User.findById(req.user._id);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const encryptedCustomId = user.encryptedCustomId;

    await EncryptedId.findOneAndDelete({ encryptedId: encryptedCustomId });

    const decryptedId = decryptCustomId(encryptedCustomId);

    const splitIds = decryptedId.split("_");
    const combinedId = splitIds.slice(0, 2).join("_");
    const combinedIds = splitIds.slice(2, 4).join("_");

    const mindoctor = await Doctor.findOne({ customId: combinedId });
    if (mindoctor) {
      mindoctor.limit -= 1;
      await mindoctor.save();
    } else {
      return res.status(404).json({
        success: false,
        message: "User is Not authorized to perform the Task",
      });
    }

    const Minnurse = await Nurse.findOne({ customId: combinedIds });
    if (Minnurse) {
      Minnurse.limit -= 1;
      await Minnurse.save();
    } else {
      return res.status(404).json({
        success: false,
        message: "User is Not authorized to perform the Task",
      });
    }

    const hashedSecondEncryptedCustom = crypto
      .createHash("sha512")
      .update(encryptedCustomId) // Assuming this is meant to be encryptedCustomId
      .digest("hex");

    const hashedcosmtomdid = crypto
      .createHash("sha256")
      .update(encryptedCustomId) // Assuming this is meant to be encryptedCustomId
      .digest("hex");

    await Symptoms_Report.findOneAndDelete({
      second_encryptedCustomId: hashedSecondEncryptedCustom,
    });

    await Medicine_Disease.findOneAndDelete({
      super_encryptedCustomId: hashedcosmtomdid,
    });

    await User.findByIdAndDelete(req.user._id);

    res.status(200).json({
      success: true,
      message: "User deleted successfully",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};
