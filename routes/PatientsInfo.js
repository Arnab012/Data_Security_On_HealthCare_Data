const express = require("express");

const {
  submitdata,
  login,
  logout,
  getProfile,
  medicinenad_report_collection,
  symptoms_report_collection,
  updateProfile,
  updatemedicinetabel,
  updatesymptomsandreport,
  deleteProfile,
} = require("../controllers/gen_info");
const authenticateToken = require("../middleware/Auth");

const router = express.Router();

router.post("/submit", submitdata);//
router.post("/login", login);//
router.get("/me", authenticateToken, getProfile);//

router.post("/logout", logout);//

router.get(
  "/medicine_diseas",
  authenticateToken,
  medicinenad_report_collection
);
router.get("/symptoms_reportt", authenticateToken, symptoms_report_collection);

router.put("/updategeneral", authenticateToken, updateProfile);//

router.put("/updatemedcinetabel", authenticateToken, updatemedicinetabel);//
router.put("/updatereport", authenticateToken, updatesymptomsandreport);
router.delete("/deleteprofile", authenticateToken, deleteProfile);

module.exports = router;
