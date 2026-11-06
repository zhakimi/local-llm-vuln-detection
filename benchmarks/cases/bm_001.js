const express = require("express");
const jwt = require("jsonwebtoken");
const app = express();

function requireUser(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"], maxAge: "1h" });
    next();
  } catch (e) {
    res.status(401).json({ error: "unauthorized" });
  }
}

app.get("/api/profile", requireUser, (req, res) => res.json(req.user));
app.listen(3000);
