const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ FRONTEND SERVE KARNA (IMPORTANT FIX)
app.use(express.static(path.join(__dirname, "../frontend")));

// Database
const db = new sqlite3.Database("users.db");

// Create table
db.run(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    authSecret TEXT
  )
`);

// Helpers
function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}

function generateAuthCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// REGISTER
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: "Missing fields" });

  const hashed = hashPassword(password);
  const secret = generateAuthCode();

  db.run(
    "INSERT INTO users (username, password, authSecret) VALUES (?, ?, ?)",
    [username, hashed, secret],
    err => {
      if (err) return res.status(400).json({ message: "User already exists" });

      res.json({
        message: "Registered & Passkey Enabled",
        authenticatorSecret: secret
      });
    }
  );
});

// LOGIN (PASSWORDLESS)
app.post("/login", (req, res) => {
  const { username, code } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, user) => {
      if (!user)
        return res.status(404).json({ message: "User not found" });

      if (code === user.authSecret) {
        res.json({ message: "Login successful (Passwordless)" });
      } else {
        res.status(401).json({ message: "Invalid authenticator code" });
      }
    }
  );
});

// START SERVER
app.listen(3000, () =>
  console.log("Server running on http://localhost:3000")
);
