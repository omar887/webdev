const jwt = require("jsonwebtoken")
function createaccesstoken(user,admin){
    const data ={
        userid :user.userid,
        isadmin:admin
    }
    const token = jwt.sign(data,secretaccesskey,{expiresIn:"15m",algorithm:"HS256"})
    return token
}
function createrefreshtoken(user,admin){
        const data ={
        userid :user.userid,
        isadmin:admin
    }
        const token = jwt.sign(data,secretrefreshkey,{expiresIn:"7d",algorithm:"HS256"})
    return token


}
module.exports= {createaccesstoken,createrefreshtoken}