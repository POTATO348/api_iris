const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");

const app = express();
app.use(cors());
app.use(bodyParser.json());

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

async function generateEmpId() {
  const [rows] = await pool.query("SELECT MAX(emp_id) AS maxId FROM tbl_user");
  let next = rows && rows[0] && rows[0].maxId ? parseInt(rows[0].maxId) + 1 : 1000;
  if (next < 1000) next = 1000;
  const [r2] = await pool.query("SELECT 1 FROM tbl_user WHERE emp_id = ?", [next]);
  if (r2.length > 0) return generateEmpId();
  return String(next);
}

app.get("/", (req, res) => res.send("✅ API running"));


app.post("/create-account", async (req, res) => {
  try {
    const { empId, firstName, middleName, lastName, suffix, email, password, confirmPassword, code } = req.body;
    if (!firstName || !lastName || !email || !password || !confirmPassword || !code) {
      return res.status(400).json({ success: false, message: "Missing required fields" });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ success: false, message: "Passwords do not match" });
    }

    const [exists] = await pool.query("SELECT user_id FROM tbl_user WHERE email = ? OR code = ?", [email, code]);
    if (exists.length > 0) return res.status(400).json({ success:false, message: "Email or code already exists" });

    const generatedEmp = empId ? empId : await generateEmpId();
    const hashed = await bcrypt.hash(password, 10);

    const insertSql = `INSERT INTO tbl_user (emp_id, first_name, middle_initial, suffix, last_name, email, password_hash, code)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const params = [generatedEmp, firstName, middleName || null, suffix || null, lastName, email, hashed, code];
    const [result] = await pool.execute(insertSql, params);

    res.status(201).json({ success: true, message: "Account created", empId: generatedEmp, insertId: result.insertId });
  } catch (err) {
    console.error("Create account error:", err);
    res.status(500).json({ success:false, message: "Internal server error", details: err.message });
  }
});

// LOGIN
app.post("/login", async (req, res) => {
  try {
    const { empId, code, password } = req.body;
    if (!empId || !code || !password) return res.status(400).json({ success:false, message:"Missing credentials" });

    const [rows] = await pool.execute("SELECT * FROM tbl_user WHERE emp_id = ? AND code = ?", [empId, code]);
    if (rows.length === 0) return res.status(401).json({ success:false, message:"Invalid credentials" });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ success:false, message:"Invalid password" });

    res.json({
      success: true,
      message: "Login successful",
      user: {
        empId: user.emp_id,
        firstName: user.first_name,
        middleName: user.middle_initial,
        lastName: user.last_name,
        email: user.email,
        code: user.code
      }
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ success:false, message: "Internal server error", details: err.message });
  }
});

// ADD BOOK
app.post("/add-book", async (req, res) => {
  try {
    const { title, author, publisher, isbn, cover_url } = req.body;
    if (!title || !isbn) return res.status(400).json({ success:false, message: "Missing title or isbn" });

    const insertSql = `INSERT INTO tbl_book (title, author, publisher, isbn, cover_url) VALUES (?, ?, ?, ?, ?)`;
    const [result] = await pool.execute(insertSql, [title, author || null, publisher || null, isbn, cover_url || null]);
    res.status(201).json({ success:true, message:"Book added", insertId: result.insertId });
  } catch (err) {
    console.error("Add book error:", err);
    res.status(500).json({ success:false, message:"Internal server error", details: err.message });
  }
});

// simple search (open library integration not needed here)
app.get("/books", async (req,res) => {
  try {
    const [rows] = await pool.execute("SELECT * FROM tbl_book ORDER BY book_id DESC");
    res.json({ success:true, data: rows });
  } catch (err) {
    res.status(500).json({ success:false, message: err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server on ${PORT}`));
