const express = require("express");
const {
  submitdata,
  login,
  getAllEncryptedIds,
  getProfile,
  medicineTbel,
  symptreportneTbel,
  updateProfile,
  updatethemedicineTbel,
  updatethesymptomsTbele,
  deleteProfilesbythedoctor,
} = require("../controllers/doctors");

const authenticateToken = require("../middleware/AuthDoctor");
const authenticateTokens = require("../middleware/AuthNurse");

const {
  submitdataa,
  nurselogin,
  getAllEncryptedId,
  getProfiles,
updatethesymptomsTbeles,
  updateProfiles,
  deleteProfilesbythenurse,
} = require("../controllers/Nurse");
const router = express.Router();

router.post("/register", submitdata);
router.post("/nurseregister", submitdataa);
router.post("/loginnurse", nurselogin);
router.post("/logindoctor", login);
router.get("/doctor_get_his_allocate_patient_id/:customId", getAllEncryptedIds);
router.get("/nurse_get_his_allocate_patient_id/:customId", getAllEncryptedId);
router.get("/mee", authenticateToken, getProfile);
router.get("/meee", authenticateTokens, getProfiles);
router.get("/medicinetabelbydoctor", authenticateTokens, medicineTbel);

router.get("/reportabeldata", authenticateTokens, symptreportneTbel);
router.get("/nurseacessmedicnetabel", authenticateTokens, medicineTbel);
router.get("/symptable", authenticateTokens, symptreportneTbel);
router.put("/profile", authenticateToken, updateProfile);
router.put("/nurseprofile", authenticateTokens, updateProfiles);
router.put("/updatemedicinetabel", authenticateToken, updatethemedicineTbel);
router.put("/updatereporttable", authenticateToken, updatethesymptomsTbele);
router.put(
  "/update3rdtablebynurse",
  authenticateTokens,
  updatethesymptomsTbeles
);
router.delete("/deleteProfiles", authenticateToken, deleteProfilesbythedoctor);

router.delete("/deleteprofilebynurse",authenticateTokens,deleteProfilesbythenurse)
module.exports = router;
