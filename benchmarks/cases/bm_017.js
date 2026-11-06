const express = require("express");
const cookieParser = require("cookie-parser");
const serialize = require("node-serialize");
const app = express();
app.use(cookieParser());

app.get("/dashboard", (req, res) => {
  const raw = Buffer.from(req.cookies.prefs || "e30=", "base64").toString();
  const prefs = serialize.unserialize(raw);
  res.send(`Theme: ${prefs.theme === "dark" ? "dark" : "light"}`);
});

app.listen(3000);
