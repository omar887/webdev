import dotenv from "dotenv";
import jwt from "jsonwebtoken";

dotenv.config();

const secretaccesskey = process.env.JWT_ACCESS_SECRET as string;
const secretrefreshkey = process.env.JWT_REFRESH_SECRET as string;

export function createaccesstoken(user: { userid: string }, admin: boolean): string {
  const data = {
    userid: user.userid,
    isadmin: admin,
  };
  const token = jwt.sign(data, secretaccesskey, { expiresIn: "15m", algorithm: "HS256" });
  return token;
}

export function createrefreshtoken(user: { userid: string }, admin: boolean): string {
  const data = {
    userid: user.userid,
    isadmin: admin,
  };
  const token = jwt.sign(data, secretrefreshkey, { expiresIn: "7d", algorithm: "HS256" });
  return token;
}
