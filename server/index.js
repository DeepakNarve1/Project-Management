import cors from "cors";
import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import morgan from "morgan";

import routes from "./routes/index.js";
dotenv.config();

const app = express();
app.use(
  cors({
    origin: process.env.CLIENT_URL,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(morgan("dev"));

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("MongoDB connection error:", err));

app.use(express.json());

const PORT = process.env.PORT || 5000;

app.get("/", (req, res) => {
  //   res.send("Welcome to the server!");
  res.status(200).json({ message: "Welcome to Project-Management API!" });
});

// http:localhost:5000/api-v1/
app.use("/api-v1", routes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res
    .status(500)
    .json({ error: "Something went wrong!(Internal server error)" });
});

// Not found middleware
app.use((req, res, next) => {
  res.status(404).json({ error: "Not Found" });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
