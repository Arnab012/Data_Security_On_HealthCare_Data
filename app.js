const express = require("express");
const cookieParser = require("cookie-parser");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);
app.use(cookieParser());

// Enable CORS for all routes
app.use(cors());
app.use(
  cors({
    origin: 4000,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
  })
);

// route imports
const user = require("./routes/PatientsInfo");
const doctor = require("./routes/doctors");
app.use("/api/v1", user);
app.use("/api/v1", doctor);

module.exports = app;
