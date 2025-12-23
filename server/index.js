import express from "express";
import cors from "cors";
import sqlite3 from "sqlite3";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import fs from "fs";

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./db.sqlite");
const SECRET = "GLENPANEL_SECRET";

// Tables
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT,
  role TEXT DEFAULT 'user'
)`);

db.run(`CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  name TEXT
)`);

// Register
app.post("/register", async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  db.run(
    "INSERT INTO users (email,password) VALUES (?,?)",
    [req.body.email, hash],
    err => {
      if (err) return res.status(400).json({ error: "User exists" });
      res.json({ success: true });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  db.get(
    "SELECT * FROM users WHERE email=?",
    [req.body.email],
    async (err, user) => {
      if (!user) return res.status(401).json({ error: "Invalid" });
      const ok = await bcrypt.compare(req.body.password, user.password);
      if (!ok) return res.status(401).json({ error: "Wrong" });

      const token = jwt.sign({ id: user.id, role: user.role }, SECRET);
      res.json({ token });
    }
  );
});

// Auth middleware
function auth(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.sendStatus(403);
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.sendStatus(401);
  }
}
