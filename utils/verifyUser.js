import { errorHandler } from "./error.js"
import jwt from "jsonwebtoken"

// Verify token middleware
export const verifyToken = (req, res, next) => {
  // Accept token from cookie or Authorization header
  let token = req.cookies.access_token || req.headers["authorization"]

  if (!token) {
    return next(errorHandler(401, "Unauthorized"))
  }

  // If header starts with "Bearer ", remove it
  if (token.startsWith("Bearer ")) {
    token = token.split(" ")[1]
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return next(errorHandler(401, "Unauthorized"))
    }

    req.user = user
    next()
  })
}

// Admin-only middleware
export const adminOnly = (req, res, next) => {
  let token = req.cookies.access_token || req.headers["authorization"]

  if (!token) {
    return next(errorHandler(401, "Unauthorized"))
  }

  if (token.startsWith("Bearer ")) {
    token = token.split(" ")[1]
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return next(errorHandler(401, "Unauthorized"))
    }

    req.user = user

    if (req.user && req.user.role === "admin") {
      next()
    } else {
      return next(errorHandler(403, "Access Denied, admin only!"))
    }
  })
}
