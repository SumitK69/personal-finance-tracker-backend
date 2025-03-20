const express = require("express");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");
const Joi = require("joi");

dotenv.config();
const app = express();
const PORT = process.env.PORT;
const JWT_SECRET = process.env.JWT_SECRET;

app.use(express.json());

// Connect to SQLite database
const db = new sqlite3.Database(
  "users.db3",
  sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE,
  (err) => {
    if (err) console.error(err.message);
    else console.log("Connected to SQLite database.");
  }
);

// Create users table if not exists
db.run(
  `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      firstname TEXT NOT NULL,
      lastname TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      db_file TEXT NOT NULL
  )`
);

// Function to create a user-specific database
const createUserDatabase = (username) => {
  const dbPath = `./dbs/${username}.db3`;

  if (!fs.existsSync("./dbs")) fs.mkdirSync("./dbs");

  const userDb = new sqlite3.Database(dbPath, (err) => {
    if (err) console.error(err.message);
  });

  // Create sample table in user DB
  userDb.serialize(() => {
    userDb.run(`CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      amount REAL,
      category TEXT,
      date TEXT
    )`);
  });

  userDb.close();
  return dbPath;
};

// **Validation Schema using Joi**
const registerSchema = Joi.object({
  firstname: Joi.string().min(2).max(50).required(),
  lastname: Joi.string().min(2).max(50).required(),
  email: Joi.string().email().required(),
  password: Joi.string()
    .min(8)
    .pattern(new RegExp("^(?=.*[A-Za-z])(?=.*\\d).{8,}$"))
    .required(),
});

// **User Registration**
app.post("/register", async (req, res) => {
  const { firstname, lastname, email, password } = req.body;

  // Validate input using Joi
  const { error } = registerSchema.validate(req.body);
  if (error) return res.status(400).json({ error: error.details[0].message });

  try {
    // Check if email already exists
    db.get(
      "SELECT email FROM users WHERE email = ?",
      [email],
      async (err, row) => {
        if (err) {
          return res.status(500).json({ error: "Database error" });
        }
        if (row) {
          return res.status(400).json({ error: "Email already registered" });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        const dbFile = createUserDatabase(email); // Assuming each user has a separate db file

        // Insert user into database
        db.run(
          "INSERT INTO users (firstname, lastname, email, password, db_file) VALUES (?, ?, ?, ?, ?)",
          [firstname, lastname, email, hashedPassword, dbFile],
          function (err) {
            if (err) {
              return res.status(500).json({ error: "Error inserting user" });
            }
            res
              .status(201)
              .json({ message: "User registered successfully", email });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// **2. User Login**
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  try {
    // Check if user exists
    db.get(
      "SELECT * FROM users WHERE email = ?",
      [email],
      async (err, user) => {
        if (err) {
          return res.status(500).json({ error: "Database error" });
        }
        if (!user) {
          return res
            .status(400)
            .json({ error: "email does not exist throw to register page" });
        }

        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(400).json({ error: "Invalid email or password" });
        }

        res.status(200).json({ message: "Login successful", email });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// **3. Guest Login**
app.post("/guest-login", (req, res) => {
  const guestUsername = `guest_${uuidv4().slice(0, 8)}`;
  const dbFile = createUserDatabase(guestUsername);

  const token = jwt.sign({ username: guestUsername, dbFile }, JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ message: "Guest login successful", guestUsername, token });
});

// **4. Get User's Database Path (Protected)**
app.get("/db-file", authenticateToken, (req, res) => {
  res.json({ dbFile: req.user.dbFile });
});

app.get("/", (req, res) => {
  res.json({ message: "hello" });
});

// **Middleware for Authentication**
function authenticateToken(req, res, next) {
  const token = req.header("Authorization");
  if (!token) return res.status(401).json({ error: "Access denied" });

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch {
    res.status(400).json({ error: "Invalid token" });
  }
}

// **Start Server**
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
