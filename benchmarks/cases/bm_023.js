const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/repo/log", (req, res) => {
  const branch = req.query.branch || "main";
  exec(`git log --oneline -n 20 ${branch}`, { cwd: "/srv/repo" }, (err, stdout) => {
    if (err) return res.status(500).send("git failed");
    res.type("text/plain").send(stdout);
  });
});

app.listen(3000);
