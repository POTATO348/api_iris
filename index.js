// index.js
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(bodyParser.json());


const pool = mysql.createPool({
  host: "tommy.heliohost.org",
  user: "zerajerzasouma14_I-ris-Manager",
  password: "SweetJesus1437~",
  database: "zerajerzasouma14_iris_db",
  port: 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});


async function generateEmpId() {
  const [rows] = await pool.query("SELECT MAX(emp_id) AS maxId FROM tbl_user");
  let next = rows && rows[0] && rows[0].maxId ? rows[0].maxId + 1 : 1000;
  if (next < 1000) next = 1000;
  const [exists] = await pool.query("SELECT 1 FROM tbl_user WHERE emp_id = ?", [next]);
  if (exists.length > 0) return generateEmpId();
  return next;
}


app.get("/", (req, res) => {
  res.send("✅ API is running successfully!");
});


app.post("/create-account", async (req, res) => {
  try {
    const {
      empId,
      firstName,
      middleName,
      lastName,
      suffix,
      email,
      password,
      confirmPassword,
      code,
    } = req.body;

   
    if (!firstName || !lastName || !email || !password || !confirmPassword || !code) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: "Passwords do not match" });
    }


    const [exists] = await pool.query("SELECT user_id FROM tbl_user WHERE email = ? OR code = ?", [email, code]);
    if (exists.length > 0) {
      return res.status(400).json({ success: false, message: "Email or code already exists" });
    }

    const generatedEmp = empId ? empId : await generateEmpId();


    const hashedPassword = await bcrypt.hash(password, 10);

    
    const insertSql = `
      INSERT INTO tbl_user
        (emp_id, first_name, middle_initial, suffix, last_name, email, password_hash, code)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      generatedEmp,
      firstName,
      middleName || null,
      suffix || null,
      lastName,
      email,
      hashedPassword,
      code,
    ];

    const [result] = await pool.execute(insertSql, params);

    return res.status(201).json({
      success: true,
      message: "Account created successfully",
      empId: generatedEmp,
      insertId: result.insertId
    });
  } catch (err) {
    console.error("Create account error:", err);
    return res.status(500).json({ success: false, message: "Internal server error", details: err.message });
  }
});


app.post("/login", async (req, res) => {
  try {
    const { empId, code, password } = req.body;
    if (!empId || !code || !password) {
      return res.status(400).json({ success: false, message: "Missing credentials" });
    }

    const [rows] = await pool.execute("SELECT * FROM tbl_user WHERE emp_id = ? AND code = ?", [empId, code]);
    if (rows.length === 0) return res.status(401).json({ success: false, message: "Invalid credentials" });

    const user = rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) return res.status(401).json({ success: false, message: "Invalid password" });

    return res.json({
      success: true,
      message: "Login successful",
      user: {
        empId: user.emp_id,
        firstName: user.first_name,
        lastName: user.last_name,
        email: user.email,
        code: user.code
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ success: false, message: "Internal server error", details: err.message });
  }
});


const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
