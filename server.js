import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import pool from "./config/db.js";
import bcrypt, { hash } from "bcrypt";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const PORT = process.env.PORT;
const SALTROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET;

// Token verifying middleware
const verifyToken = (req, res, next) => {
    const token = req.headers["authorization"]?.split(" ")[1];

    if(!token) {
        return res.status(401).json({message: "No token provided."});
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        console.log(decoded);
        next();
    } catch (error) {
        res.status(403).json({message: "Invalid token."});
    }
}

//Middleware
app.use(cors());
app.use(bodyParser.json());

// Home-page
app.get("/", (req, res) => {
    res.send("Backend is working!");
});

app.get("/test-db", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");
        res.send(result.rows);
    } catch (error) {
        console.error("Error executing query", error);
        res.status(500).send("Internal Server Error");
    }
});

// Get a user by id
app.get("/users/:id", async (req, res) => {
    const {id} = req.params;

    try {
        const result = await pool.query("SELECT * FROM users WHERE id=$1", [id]);
        if (result.rowCount === 0
        ) {
            res.status(404).json({message: "User Not Found"});
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).send("Internal Server Error");
    }
});

// Get all Posts
app.get("/posts", async (req, res) => {
    try {
        const result = await pool.query("SELECT * FROM posts");

        if (result.rowCount === 0) {
            res.status(404).json({message: "Posts not Found"});
        }
        res.json(result.rows);
    } catch (error) {
        console.error("Error getting posts", error);
        res.status(500).json({message: "Internal Server Error"});
    }
});

// Get a Post by id
app.get("/posts/:id", async (req, res) => {
    const {id} = req.params;

    try {
        const result = await pool.query("SELECT * FROM posts WHERE id=$1", [id]);

        if (result.rowCount === 0) {
            res.status(404).json({message: "Post not found"});
        }
        res.json(result.rows[0]);
    } catch (error) {
        console.error("Error getting post", error);
        res.status(500).json({message: "Internal Server Error"});
    }
});

//Create a User
app.post("/users", async (req, res) => {
    // getting data from request body
    console.log(req.body);
    const {username, email, password} = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: "All fields are required."});
    }

    try {
        // Check if user already exists in the database
        const exists = await pool.query(
            "SELECT * FROM users WHERE email=$1",
            [email]
        );
        if (exists.rowCount > 0) {
            return res.status(400).json({message: "Email is already registered"});
        }

        // Hash the password
        const hashedPasswrod = await bcrypt.hash(password, SALTROUNDS);

        const result = await pool.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [username, email, hashedPasswrod]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error("Error registering user", error.message);
        res.status(500).json({message: "Internal Server Error"});
    }
});

// Login
app.post("/login", async (req, res) => {
    const {email, password} = req.body;

    try {
        // Check if user exists
        const request = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
        const user = request.rows[0];
        console.log(user);

        if (!user) {
            return res.status(400).json({message: "User not found"});
        }

        // Compare user typed password with stored password
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if(!isPasswordValid) {
            return res.status(401).json({message: "Incorrect password."});
        }

        // Generate a JWT token
        const token = jwt.sign({id: user.id, email: user.email}, JWT_SECRET, {expiresIn: "3h"});

        res.status(200).json({message: "Login successful", token});
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({message: "internal server error."});
    }
});

// Create a Post
app.post("/posts", verifyToken, async (req, res) => {
    const {post_title, post_content} = req.body;
    
    if (!post_title || !post_content) {
        return res.status(400).json({message: "All fields are required"});
    }

    try {
        const result = await pool.query(
            "INSERT INTO posts (post_title, post_content, user_id) VALUES ($1, $2, $3) RETURNING *",
            [post_title, post_content, req.user.id]
        )
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error("Error creating post", error);
        res.status(500).json({message: "Internal Server Error"});
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});