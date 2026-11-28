const jwt = require('jsonwebtoken')
function verifytoken(req,res,next){
    const accesstoken = req.cookies.accesstoken
    try{
    const results = jwt.verify(accesstoken,secretaccesskey)
    req.user = {id:results.userid,isadmin:results.isadmin}
    next()
    }
    catch(err){
        return res.status(401).json({error:"notgood"})
    }
    
}
module.exports = verifytoken