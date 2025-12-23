import express from "express"
import cors from "cors"
import dotenv from "dotenv"
import mongoose from "mongoose"
import cookieParser from "cookie-parser"
import path from "path"
import { fileURLToPath } from "url"

// Routes
import authRoutes from "./routes/auth.route.js"
import userRoutes from "./routes/user.route.js"
import taskRoutes from "./routes/task.route.js"
import reportRoutes from "./routes/report.route.js"

// Load env variables
dotenv.config()

// Fix __dirname for ES modules
const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

const app = express()

/* =======================
   Database Connection
======================= */
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("Database is connected"))
  .catch((err) => console.error("MongoDB error:", err))

/* =======================
   Middleware
======================= */

// CORS (supports cookies + JWT)
app.use(
  cors({
    origin: [
      "https://task-managerapp-frontend.netlify.app", // local frontend
      process.env.FRONT_END_URL, // deployed frontend
    ],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
)

app.use(express.json())
app.use(cookieParser())

/* =======================
   Routes
======================= */

app.use("/api/auth", authRoutes)
app.use("/api/users", userRoutes)
app.use("/api/tasks", taskRoutes)
app.use("/api/reports", reportRoutes)

/* =======================
   Static Files
======================= */
app.use("/uploads", express.static(path.join(__dirname, "uploads")))

/* =======================
   Error Handler (LAST)
======================= */
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500
  const message = err.message || "Internal Server Error"

  res.status(statusCode).json({
    success: false,
    statusCode,
    message,
  })
})

/* =======================
   Start Server
======================= */
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}!`)
})
