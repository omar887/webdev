import dotenv from "dotenv";
import { NextFunction, Request, Response } from "express";
import jwt, { JwtPayload } from "jsonwebtoken";

dotenv.config();

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        isadmin: boolean;
      };
    }
  }
}

const secretaccesskey = process.env.JWT_ACCESS_SECRET as string;

export default function verifytoken(req: Request, res: Response, next: NextFunction) {
  const accesstoken = req.cookies?.accesstoken;
  if (!accesstoken) {
    return res.status(401).json({ error: "notgood" });
  }

  try {
    const results = jwt.verify(accesstoken, secretaccesskey) as JwtPayload;
    req.user = { id: results.userid, isadmin: results.isadmin };
    next();
  } catch (err) {
    return res.status(401).json({ error: "notgood" });
  }
}
