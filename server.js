// app.js
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const passport = require("passport");
const dotenv = require("dotenv");
const db = require("./db/db");
const PORT = process.env.PORT;
const app = express();
dotenv.config();
app.use(cors());
app.use(bodyParser.json());

require("./config/passport")(passport);
require("./routes/authRoutes")(app, passport);

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
