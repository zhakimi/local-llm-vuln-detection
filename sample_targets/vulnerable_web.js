/*
 * !!! INTENTIONALLY VULNERABLE CODE — FOR SCANNER TESTING ONLY. DO NOT DEPLOY. !!!
 *
 * Small Express API used as a scan target for amd-vuln-scanner.
 */

const express = require("express");
const jwt = require("jsonwebtoken");
const { exec } = require("child_process");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json());

const JWT_SECRET = "changeme123";

// Reflected search page
app.get("/search", (req, res) => {
  const q = req.query.q || "";
  res.send(`<html><body><h1>Results for ${q}</h1></body></html>`);
});

// Profile page renders bio directly into HTML
app.get("/profile/:name", (req, res) => {
  const bio = req.query.bio;
  res.setHeader("Content-Type", "text/html");
  res.end("<div class='bio'>" + bio + "</div><p>User: " + req.params.name + "</p>");
});

// Network diagnostics
app.get("/api/lookup", (req, res) => {
  const domain = req.query.domain;
  exec("nslookup " + domain, (err, stdout, stderr) => {
    if (err) return res.status(500).send(stderr);
    res.send(stdout);
  });
});

// Archive a user's directory
app.post("/api/archive", (req, res) => {
  const { folder } = req.body;
  exec(`tar -czf /tmp/backup.tgz /home/app/data/${folder}`, (err) => {
    res.json({ ok: !err });
  });
});

// Token verification accepts any algorithm the client chooses, including "none"
function authenticate(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, JWT_SECRET, { algorithms: ["HS256", "none"] });
    next();
  } catch (e) {
    res.status(401).json({ error: "unauthorized" });
  }
}

// Admin check trusts an unverified token payload
app.get("/api/admin", (req, res) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  const payload = jwt.decode(token);
  if (payload && payload.role === "admin") {
    return res.json({ secret: "admin dashboard data" });
  }
  res.status(403).json({ error: "forbidden" });
});

app.get("/api/me", authenticate, (req, res) => {
  res.json(req.user);
});

// Static file reader
app.get("/files", (req, res) => {
  const file = path.join(__dirname, "public", req.query.name);
  res.send(fs.readFileSync(file, "utf8"));
});

// Dynamic report filter
app.post("/api/filter", (req, res) => {
  const fn = new Function("item", "return " + req.body.expression);
  res.json([1, 2, 3].filter(fn));
});

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

app.listen(3000, () => console.log("listening on 3000"));
