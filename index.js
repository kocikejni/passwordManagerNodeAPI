const mysql = require("mysql2");
const PORT = 3001;
const cors = require("cors");
const express = require("express");
const app = express();
const jsonwebtoken = require("jsonwebtoken");
const db = mysql.createConnection({
  user: "root",
  host: "localhost",
  password: "notMyRealPassword",
  database: "passwordmanager",
});

const { encrypt, decrypt } = require("./EncryptionHandler");
const JWT_SECRET = "SMzab9*hebBm$R8$";

app.use(cors());
app.use(express.json());

app.post("/addpassword", (req, res) => {
  const { password, title, email } = req.body;
  const hashedPassword = encrypt(password);
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jsonwebtoken.verify(token, JWT_SECRET);
    const userEmail = decoded.user;

    if (!userEmail) {
      res.status(401).send("Unauthorized");
      return;
    } else {
      console.log(userEmail);
    }

    db.query(
      "INSERT INTO passwords (password, title, iv, userEmail, email) VALUES (?, ?, ?, ?, ?)",
      [hashedPassword.password, title, hashedPassword.iv, userEmail, email],
      (err, result) => {
        if (err) {
          console.log(err);
          res.status(500).send("Server error");
        } else {
          res.send({ success: true });
        }
      }
    );
  } catch (error) {
    res.status(401).send("Invalid token");
  }
});

app.put("/updatepassword", (req, res) => {
  const { password, title, email, id } = req.body; 
  const hashedPassword = encrypt(password);
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jsonwebtoken.verify(token, JWT_SECRET);
    const userEmail = decoded.user;

    if (!userEmail) {
      res.status(401).send("Unauthorized");
      return;
    } else {
      console.log(userEmail);
    }

    db.query(
      "UPDATE passwords SET password = ?, title = ?, email = ? WHERE id = ? AND userEmail = ?",
      [hashedPassword.password, title, email, id, userEmail], 
      (err, result) => {
        if (err) {
          console.log(err);
          res.status(500).send("Server error");
        } else {
          if (result.affectedRows === 0) {
            res.status(404).send("Password not found");
          } else {
            res.send({ success: true });
          }
        }
      }
    );
  } catch (error) {
    res.status(401).send("Invalid token");
  }
});


app.delete("/deletepassword", (req, res) => {
  const { id, email } = req.body;
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jsonwebtoken.verify(token, JWT_SECRET);
    const userEmail = decoded.user;

    if (!userEmail) {
      res.status(401).send("Unauthorized");
      return;
    } else {
      console.log(userEmail);
    }

    db.query(
      "DELETE FROM passwords WHERE id = ? AND userEmail = ? AND email = ?",
      [id, userEmail, email],
      (err, result) => {
        if (err) {
          console.log(err);
          res.status(500).send("Server error");
        } else if (result.affectedRows === 0) {
          res.status(404).send("Password not found");
        } else {
          res.send({ success: true });
        }
      }
    );
  } catch (error) {
    res.status(401).send("Invalid token");
  }
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
            const token = jsonwebtoken.sign({ user: email }, JWT_SECRET, {
              expiresIn: "1h",
            });

            res.send({ success: true, token: token });
          } else {
            res.status(401).send("Invalid email or password");
          }
        }
      }
    }
  );
});

const invalidatedTokens = [];

app.post("/logout", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    res.status(401).send("Unauthorized");
    return;
  }

  if (invalidatedTokens.includes(token)) {
    res.status(401).send("Token has already been invalidated");
    return;
  }

  invalidatedTokens.push(token);

  res.send({ success: true });
});

app.get("/getpasswords", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jsonwebtoken.verify(token, JWT_SECRET);
    const userEmail = decoded.user;

    if (!userEmail) {
      res.status(401).send("Unauthorized");
      return;
    } else {
      console.log(userEmail);
    }

    db.query(
      "SELECT * FROM passwords WHERE userEmail = ?;",
      [userEmail],
      (err, result) => {
        if (err) {
          console.log(err);
          res.status(500).send("Server error");
        } else {
          const decryptedPasswords = result.map((password) => {
            const decryptedPassword = decrypt({
              password: password.password,
              iv: password.iv,
            });
            return {
              ...password,
              password: decryptedPassword,
            };
          });
          res.send(decryptedPasswords);
        }
      }
    );
  } catch (error) {
    res.status(401).send("Invalid token");
  }
});

app.get("/getpassword/:id", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  try {
    const decoded = jsonwebtoken.verify(token, JWT_SECRET);
    const userEmail = decoded.user;

    if (!userEmail) {
      res.status(401).send("Unauthorized");
      return;
    }

    const passwordId = req.params.id;

    db.query(
      "SELECT * FROM passwords WHERE id = ? AND userEmail = ?;",
      [passwordId, userEmail],
      (err, result) => {
        if (err) {
          console.log(err);
          res.status(500).send("Server error");
        } else {
          if (result.length === 0) {
            res.status(404).send("Password not found");
          } else {
            const decryptedPassword = decrypt({
              password: result[0].password,
              iv: result[0].iv,
            });
            const decryptedResult = {
              ...result[0],
              password: decryptedPassword,
            };
            res.send(decryptedResult);
          }
        }
      }
    );
  } catch (error) {
    res.status(401).send("Invalid token");
  }
});

app.post("/decryptpassword", (req, res) => {
  res.send(decrypt(req.body));
});

app.listen(PORT, () => {
  console.log("server is running");
});
