const axios = require('axios')
base = baseurl
const api = axios.create({baseURL:base},{withCredentials:true})

module.exports=api
