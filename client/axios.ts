import axios from "axios";

const base = "/api";
const api = axios.create({ baseURL: base, withCredentials: true });

export default api;
