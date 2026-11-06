const express = require("express");
const cors = require("cors");
const session = require("express-session");
const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(session({ secret: "keyboard-cat-2019", resave: false, saveUninitialized: false }));

app.get("/api/account", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.listen(3000);
