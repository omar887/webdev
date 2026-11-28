import crypto from "crypto";
import argon2 from "argon2";
import { CookieOptions, Request, Response, Router } from "express";
import jwt from "jsonwebtoken";
import verifytoken from "./authenticate";
import { createaccesstoken, createrefreshtoken } from "./createtoken";
import pool from "./db";

const router = Router();

const cookieOptions: CookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "lax",
};

interface UserRow {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  avatar_url: string | null;
  bio: string;
  created_at: Date;
}

interface RefreshTokenJoinRow {
  id: string;
  user_id: string;
  revoked_at: Date | null;
  expires_at: Date;
}

function hashToken(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

// Register new account
router.post("/register", async (req: Request, res: Response): Promise<void> => {
  try {
    const username: string | undefined = req.body?.username?.trim();
    const email: string | undefined = req.body?.email?.trim().toLowerCase();
    const password: string | undefined = req.body?.password;

    if (!username || !email || !password) {
      res.status(400).json({ message: "Username, email, and password are required" });
      return;
    }

    if (password.length < 8) {
      res.status(400).json({ message: "Password must be at least 8 characters" });
      return;
    }

    const existing = await pool.query<{ id: string }>(
      "SELECT id FROM users WHERE LOWER(email) = $1 OR LOWER(username) = LOWER($2)",
      [email, username]
    );

    if (existing.rows.length > 0) {
      res.status(409).json({ message: "Username or email already taken" });
      return;
    }

    const passwordHash = await argon2.hash(password);

    const userResult = await pool.query<Omit<UserRow, "password_hash">>(
      `INSERT INTO users (username, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, username, email, avatar_url, bio, created_at`,
      [username, email, passwordHash]
    );

    const user = userResult.rows[0];
    const accesstoken = createaccesstoken({ userid: user.id }, false);
    const refreshtoken = createrefreshtoken({ userid: user.id }, false);
    const tokenHash = hashToken(refreshtoken);

    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [user.id, tokenHash]
    );

    res.cookie("accesstoken", accesstoken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
    res.cookie("refreshtoken", refreshtoken, {
      ...cookieOptions,
      path: "/api/auth",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(201).json({ accesstoken, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login existing user
router.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const identifier: string | undefined = req.body?.identifier?.trim();
    const password: string | undefined = req.body?.password;

    if (!identifier || !password) {
      res.status(400).json({ message: "Email/username and password are required" });
      return;
    }

    const userResult = await pool.query<UserRow>(
      `SELECT id, username, email, password_hash, avatar_url, bio, created_at
       FROM users
       WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($1)`,
      [identifier]
    );

    const userRow = userResult.rows[0];
    if (!userRow) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    const validPassword = await argon2.verify(userRow.password_hash, password);
    if (!validPassword) {
      res.status(401).json({ message: "Invalid credentials" });
      return;
    }

    const accesstoken = createaccesstoken({ userid: userRow.id }, false);
    const refreshtoken = createrefreshtoken({ userid: userRow.id }, false);
    const tokenHash = hashToken(refreshtoken);

    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [userRow.id, tokenHash]
    );

    const { password_hash: _ignored, ...user } = userRow;

    res.cookie("accesstoken", accesstoken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
    res.cookie("refreshtoken", refreshtoken, {
      ...cookieOptions,
      path: "/api/auth",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ accesstoken, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Refresh access token using refresh cookie
router.post("/refresh", async (req: Request, res: Response): Promise<void> => {
  try {
    const oldRefresh: string | undefined = req.cookies?.refreshtoken;
    if (!oldRefresh) {
      res.status(401).json({ message: "Missing refresh token" });
      return;
    }

    try {
      jwt.verify(oldRefresh, process.env.JWT_REFRESH_SECRET as string, {
        algorithms: ["HS256"],
      });
    } catch {
      res.clearCookie("accesstoken", cookieOptions);
      res.clearCookie("refreshtoken", { ...cookieOptions, path: "/api/auth" });
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    const oldHash = hashToken(oldRefresh);

    const tokenResult = await pool.query<RefreshTokenJoinRow>(
      `SELECT id, user_id, revoked_at, expires_at
       FROM refresh_tokens
       WHERE token_hash = $1`,
      [oldHash]
    );

    const tokenRow = tokenResult.rows[0];
    if (!tokenRow || tokenRow.revoked_at || new Date(tokenRow.expires_at) <= new Date()) {
      res.clearCookie("accesstoken", cookieOptions);
      res.clearCookie("refreshtoken", { ...cookieOptions, path: "/api/auth" });
      res.status(401).json({ message: "Invalid or expired refresh token" });
      return;
    }

    const newRefresh = createrefreshtoken({ userid: tokenRow.user_id }, false);
    const newHash = hashToken(newRefresh);

    await pool.query("UPDATE refresh_tokens SET revoked_at = NOW() WHERE id = $1", [tokenRow.id]);
    await pool.query(
      `INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '7 days')`,
      [tokenRow.user_id, newHash]
    );

    const accesstoken = createaccesstoken({ userid: tokenRow.user_id }, false);

    res.cookie("accesstoken", accesstoken, { ...cookieOptions, maxAge: 15 * 60 * 1000 });
    res.cookie("refreshtoken", newRefresh, {
      ...cookieOptions,
      path: "/api/auth",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    res.status(200).json({ accesstoken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Logout current session
router.post("/logout", async (req: Request, res: Response): Promise<void> => {
  try {
    const refreshtoken: string | undefined = req.cookies?.refreshtoken;
    if (refreshtoken) {
      const tokenHash = hashToken(refreshtoken);
      await pool.query(
        "UPDATE refresh_tokens SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL",
        [tokenHash]
      );
    }

    res.clearCookie("accesstoken", cookieOptions);
    res.clearCookie("refreshtoken", { ...cookieOptions, path: "/api/auth" });
    res.status(200).json({ message: "Logged out" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Get logged-in user profile
router.get("/me", verifytoken, async (req: Request, res: Response): Promise<void> => {
  try {
    const result = await pool.query<Omit<UserRow, "password_hash">>(
      `SELECT id, username, email, avatar_url, bio, created_at
       FROM users
       WHERE id = $1`,
      [req.user!.id]
    );

    if (result.rows.length === 0) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.status(200).json({ user: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
