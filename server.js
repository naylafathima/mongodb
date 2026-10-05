const express = require("express");
const fs = require("fs");
const EventEmitter = require("events");
const path = require("path");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;

// Audit log file
const auditFile = path.join(__dirname, "audit.log");

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ===============================
// MongoDB Connection
// ===============================

mongoose
    .connect("mongodb://127.0.0.1:27017/myapp")
    .then(() => {
        console.log("MongoDB connected successfully");
    })
    .catch((error) => {
        console.error("MongoDB connection error:", error);
    });

// ===============================
// User Schema / Model
// ===============================

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true
        },

        email: {
            type: String,
            required: true,
            unique: true
        },

        password: {
            type: String,
            required: true
        }
    },
    {
        timestamps: true
    }
);

const User = mongoose.model("User", userSchema);

// ===============================
// EventEmitter
// ===============================

const userEvents = new EventEmitter();

// Signup event
userEvents.on("signup", (user) => {
    const message =
        `[${new Date().toLocaleString()}] SIGNUP: ${user.name} (${user.email})\n`;

    fs.appendFileSync(auditFile, message);
});

// Login event
userEvents.on("login", (user) => {
    const message =
        `[${new Date().toLocaleString()}] LOGIN: ${user.name} (${user.email})\n`;

    fs.appendFileSync(auditFile, message);
});

// ===============================
// Sign Up Route
// ===============================

app.post("/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required."
            });
        }

        // Check if email already exists
        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({
                message: "Email already registered."
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user
        const newUser = await User.create({
            name,
            email,
            password: hashedPassword
        });

        // Emit signup event
        userEvents.emit("signup", newUser);

        res.json({
            message: "Registration successful!"
        });

    } catch (error) {
        console.error("Signup error:", error);

        res.status(500).json({
            message: "Server error during registration."
        });
    }
});

// ===============================
// Login Route
// ===============================

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required."
            });
        }

        // Find user by email
        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Compare entered password with hashed password
        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password."
            });
        }

        // Emit login event
        userEvents.emit("login", user);

        res.json({
            message: "Login successful!",
            name: user.name
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Server error during login."
        });
    }
});

// ===============================
// Start Server
// ===============================

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});