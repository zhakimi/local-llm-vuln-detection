const express = require("express");
const mysql = require("mysql2");
const app = express();
const pool = mysql.createPool({ host: "db", user: "app", database: "crm", password: process.env.DB_PASSWORD });

app.get("/customers/:id", (req, res) => {
  const sql = "SELECT name, email FROM customers WHERE id = " + req.params.id;
  pool.query(sql, (err, rows) => {
    if (err) return res.status(500).end();
    res.json(rows);
  });
});

app.listen(3000);
