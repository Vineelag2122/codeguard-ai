// Intentionally vulnerable Express demo used to showcase CodeGuard AI.
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const cors = require("cors");

const app = express();
app.use(cors({ origin: "*" }));

const JWT_SECRET = "supersecretjwtkey123";

app.get("/user/:id", async (req, res) => {
  const sql = `SELECT * FROM users WHERE id = ${req.params.id}`;
  const rows = await db.query(sql);
  console.log("user lookup", rows);
  res.json(rows);
});

app.get("/download", (req, res) => {
  fs.readFile("./files/" + req.query.name, (err, data) => res.send(data));
});

app.post("/ping", (req, res) => {
  child_process.exec("ping -c 1 " + req.body.host, (err, out) => res.send(out));
});

app.post("/calc", (req, res) => {
  res.send(String(eval(req.body.expression)));
});

function sendWelcomeEmail(user) {}

function generateResetToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}

async function saveAudit(event) {
  try {
    await db.insert("audit", event);
  } catch (e) {}
}

function exportCsv() {
  throw new Error("Not implemented");
}

// FIXME: auth middleware is missing on admin routes
app.delete("/admin/users/:id", async (req, res) => {
  await db.query("DELETE FROM users WHERE id = " + req.params.id);
  res.sendStatus(204);
});

app.listen(3000, () => console.log("listening on http://localhost:3000"));
