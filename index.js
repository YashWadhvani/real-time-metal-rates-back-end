const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const User = require("./models/User");
const cors = require("cors");
const bodyParser = require("body-parser");
const morgan = require("morgan");

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(morgan("combined"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware to authenticate the token and set req.user
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send("Unauthorized: Missing or invalid token");
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // decoded token contains userId
    next();
  } catch (err) {
    console.error("JWT verification error:", err);
    return res.status(401).send("Unauthorized: Invalid token");
  }
};

app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).send("All fields are required");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ name, email, password: hashedPassword });
  await user.save();
  res.status(201).send("User created");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(400).send("Invalid login credentials");
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).send("Invalid login credentials");
  }

  const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
  res.send({ token });
});

app.get("/protected", authenticateToken, async (req, res) => {
  const userId = req.user.userId;

  const user = await User.find({ _id: `${userId}` });
  if (!user) {
    return res.status(404).send("User not found");
  }

  // const { password, ...userData } = user.toObject(); // Exclude password from response
  res.json({ message: "Protected content", user });
});

app.put("/update", authenticateToken, async (req, res) => {
  const { name, email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = req.user.userId; // Get user ID from the token

  const update = {
    name,
    email,
    password: hashedPassword,
  };

  await User.updateOne({ _id: userId }, update);
  res.send("User updated");
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
