const express = require("express");
const app = express();

app.get("/search", (req, res) => {
  const term = req.query.q || "";
  res.send(`<h2>Results for ${term}</h2><ul id="results"></ul>`);
});

app.listen(3000);
