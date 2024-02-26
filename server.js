const app = require("./app");
const dotenv = require("dotenv");
const connecttoMongo = require("./config/db");

// config
dotenv.config({ path: "backend/config/.env" });
connecttoMongo();

app.listen(process.env.PORT, () => {
  console.log(`server is workung on http://localhost:${process.env.PORT}`);
});
