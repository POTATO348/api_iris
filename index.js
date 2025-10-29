require('dotenv').config();
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// ✅ CONNECT TO DATABASE
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// ✅ TEST ROUTE
app.get("/", (req, res) => {
  res.send("✅ API is running successfully!");
});

// ✅ CREATE ACCOUNT
app.post("/create-account", async (req, res) => {
  try {
    const { firstName, middleInitial, lastName, email, password, confirmPassword, code } = req.body;

    if (!firstName || !lastName || !email || !password || !confirmPassword || !code) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const query = `
      INSERT INTO tbl_user 
        (first_name, middle_initial, last_name, email, password_hash, code)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const [result] = await pool.execute(query, [
      firstName,
      middleInitial || null,
      lastName,
      email,
      hashedPassword,
      code
    ]);

    res.status(201).json({
      message: "✅ Account created successfully",
      empId: result.insertId
    });

  } catch (err) {
    console.error("Error creating account:", err);
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ error: "Email or code already exists" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ LOGIN
app.post("/login", async (req, res) => {
  try {
    const { empId, code, password } = req.body;

    if (!empId || !code || !password) {
      return res.status(400).json({ error: "EmpID, code, and password are required" });
    }

    const [rows] = await pool.execute(
      "SELECT * FROM tbl_user WHERE user_id = ? AND code = ?",
      [empId, code]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ error: "Invalid password" });
    }

    res.json({
      message: "✅ Login successful",
      user: {
        id: user.user_id,
        name: `${user.first_name} ${user.last_name}`,
        email: user.email,
        code: user.code
      }
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ FETCH USERS (optional)
app.get("/users", async (req, res) => {
  try {
    const [rows] = await pool.execute("SELECT * FROM tbl_user ORDER BY user_id ASC");
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ✅ START SERVER
const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running at http://0.0.0.0:${PORT}`);
});
