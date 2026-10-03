import express, { json } from "express";
import cors from "cors";
import mysql from "mysql2";
import { config } from "dotenv";
import jwt from "jsonwebtoken";
config();
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 10,
});

const db = pool.promise();

const app = express();
app.use(cors());

app.use(express.json());

app.post("/api/register", async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res
      .status(401)
      .json({ message: "Username, password, dan role tidak boleh kosong" });
  }
  //check if username is exist
  try {
    const sql = "SELECT * FROM users WHERE username = ? ";
    const [rows] = await db.query(sql, [username]);
    if(rows.length === 1){
      return res.status(400).json("Username sudah terpakai")
    }
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
  // create new user
  try {
    const [result] = await db.query(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
      [username, password, role],
    );
    console.log(result);

    res.json({
      message: "Data user berhasil ditambahkan",
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await db.query(
      "SELECT * FROM users WHERE username = ? AND password = ?",
      [username, password],
    );

    if (rows.length !== 1) {
      return res.status(401).json({ message: "Username atau password salah" });
    }
    const payload = {
      id: rows[0].id,
      username: rows[0].username,
      role: rows[0].role,
    };

    const token = jwt.sign(payload, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.json({ message: "Login berhasil", token });
  } catch (error) {
    return res.json({ message: error.message });
  }
});

app.get(
  "/api/profile",
  (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Akses ditolak" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decodedUser) => {
      if (err) {
        return res
          .status(403)
          .json({ message: "Token tidak valid atau kadaluwarsa" });
      }
      req.user = decodedUser;
      next();
    });
  },
  (req, res) => {
    res.json({
      message: "Ini adalah data rahasia profil pengguna",
      user: req.user,
    });
  },
);

const port = 5000;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
