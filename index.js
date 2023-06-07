const express = require("express");
const app = express();
const mysql = require("mysql2");
const PORT = 3001;
const cors = require("cors");
const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "Android_50th",
  database: "passwordmanager",
});

const { encrypt, decrypt } = require("./EncryptionHandler");

app.use(cors());
app.use(express.json());

app.post("/addpassword", (req, res) => {
  const { password, title } = req.body;
  const hashedPassword = encrypt(password);
  db.query(
    "INSERT INTO passwords (password, title, iv) VALUES (?, ?, ?)",
    [hashedPassword.password, title, hashedPassword.iv],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send("Success");
      }
    }
  );
});

app.post("/register", (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = encrypt(password);
  db.query(
    "INSERT INTO accounts (email, password, iv) VALUES (?, ?, ?)",
    [email, hashedPassword.password, hashedPassword.iv],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send("Success");
      }
    }
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.query(
    "SELECT * FROM accounts WHERE email = ?",
    [email],
    (err, results) => {
      if (err) {
        console.log(err);
        res.status(500).send("Server error");
      } else {
        if (results.length === 0) {
          res.status(401).send("Email not found");
        } else {
          const storedPassword = results[0].password;
          const storedIV = results[0].iv;
          const decryptedPassword = decrypt({
            password: storedPassword,
            iv: storedIV,
          });

          if (password === decryptedPassword) {
            res.send("Login successful!");
          } else {
            res.status(401).send("Invalid email or password");
          }
        }
      }
    }
  );
});

app.get("/getpasswords", (req, res) => {
  db.query("SELECT * FROM passwords;", (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.send(result);
    }
  });
});

app.post("/decryptpassword", (req, res) => {
  res.send(decrypt(req.body));
});

app.listen(PORT, () => {
  console.log("server is running");
});
