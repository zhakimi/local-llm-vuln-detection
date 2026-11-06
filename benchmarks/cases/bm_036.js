const express = require("express");
const app = express();

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

app.get("/search", (req, res) => {
  const term = req.query.q || "";
  res.send(`<h2>Results for ${escapeHtml(term)}</h2><ul id="results"></ul>`);
});

app.listen(3000);
