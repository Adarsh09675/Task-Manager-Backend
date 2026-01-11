import jwt from "jsonwebtoken";
import { errorHandler } from "./error.js";

// ================= VERIFY TOKEN =================
export const verifyToken = (req, res, next) => {
  const token = req.cookies?.access_token;

  if (!token) {
    return next(errorHandler(401, "Unauthorized - No token"));
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return next(errorHandler(401, "Unauthorized - Invalid token"));
    }

    req.user = decoded; // { id, role, iat, exp }
    next();
  });
};

// ================= ADMIN ONLY =================
export const adminOnly = (req, res, next) => {
  if (!req.user) {
    return next(errorHandler(401, "Unauthorized"));
  }

  if (req.user.role !== "admin") {
    return next(errorHandler(403, "Access denied - Admin only"));
  }

  next();
};
