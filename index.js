const express = require("express");
const app = express();
const mysql = require("mysql2");
const PORT = 3001;
const cors = require('cors')
const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "Android_50th",
  database: "passwordmanager",
});

app.use(cors())
app.use(express.json())

app.post("/addpassword", (req, res) => {
  const { password, title } = req.body;

  db.query(
    "INSERT INTO passwords (password, title) VALUES (?, ?)",
    [password, title],
    (err, result) => {
      if (err) {
        console.log(err);
      } else {
        res.send("Success");
      }
    }
  );
});

app.listen(PORT, () => {
  console.log("server is running");
});