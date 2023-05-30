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
