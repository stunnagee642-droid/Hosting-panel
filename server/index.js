import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import sqlite3 from "sqlite3";

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./db.sqlite");

// Create users table
db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
)
`);

const SECRET = "hosting_panel_secret";

// Register
app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (email, password) VALUES (?,?)",
    [email, hash],
    err => {
      if (err) return res.status(400).json({ error: "User exists" });
      res.json({ success: true });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE email=?",
    [email],
    async (err, user) => {
      if (!user) return res.status(401).json({ error: "Invalid login" });

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).json({ error: "Wrong password" });

      const token = jwt.sign({ id: user.id }, SECRET);
      res.json({ token });
    }
  );
});

// Dashboard test
app.get("/dashboard", (req, res) => {
  res.json({ status: "Hosting panel running 🚀" });
});

app.listen(3000, () => console.log("Server running on port 3000"));
