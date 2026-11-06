const express = require("express");
const { execFile } = require("child_process");
const app = express();

const BRANCH_RE = /^[A-Za-z0-9._\/-]{1,64}$/;

app.get("/repo/log", (req, res) => {
  const branch = req.query.branch || "main";
  if (!BRANCH_RE.test(branch) || branch.startsWith("-")) return res.status(400).send("bad branch");
  execFile("git", ["log", "--oneline", "-n", "20", branch, "--"], { cwd: "/srv/repo" }, (err, stdout) => {
    if (err) return res.status(500).send("git failed");
    res.type("text/plain").send(stdout);
  });
});

app.listen(3000);
