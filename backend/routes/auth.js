const express = require('express');
const router = express.Router();
const User = require('../models/User')
const { body, validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');
var jwt = require('jsonwebtoken');
const fetchuser = require('../middleware/fetchuser');

const JWT_SECRET = 'Sharathisagoodb$oy';


//ROUTE 1 : create a user using post request  "/api/auth/createuser". No login required
router.post('/createuser',[
    body('name', 'enter a valid name').isLength({min:3}),
    body('password', 'password must be at least 8 characters long').isLength({min:8}),
    body('email', 'enter a valid email').isEmail(),
],  async (req,res)=>{
    
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({errors : errors.array()});
    }
    //check whether the email id already exists
    try{
    let user = await User.findOne({email : req.body.email});
    if(user){
        return res.status(400).json({error:"A user with this email already exists"});
    }
    
    const salt = await bcrypt.genSalt(10);
    const secPass = await bcrypt.hash(req.body.password, salt);
    //create a new user
    user = await User.create({
        name: req.body.name,
        password: secPass,
        email : req.body.email,
    });
    const data = {
        user:{
            id : user.id
        }
    }
    const authtoken = jwt.sign(data, JWT_SECRET);
    res.json({authtoken});
    }catch(error){
        console.error(error.message);
        res.status(500).send("Some error occurred");
    }
    //json webtoken - a method to verify a user
    //the third segment of the webtoken is a secret signature, which allows us to identify any tampering
})


//ROUTE 2 : authenticate a user using post request  "/api/auth/login". No login required
router.post('/login',[
    body('email', 'enter a valid email').isEmail(),
    body('password', 'Password cannot be blank').exists()

],  async (req,res)=>{
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({errors : errors.array()});
    }
    const {email, password} = req.body;
    try {
        let user = await User.findOne({email});
        if(!user){
            return res.status(400).json({error:"Please login with the correct credentials"});
        }

        const passwordCompare = await bcrypt.compare(password, user.password);
        if(!passwordCompare){
            return res.status(400).json({error:"Please login with the correct credentials"});
        }

        const data = {
            user:{
                id : user.id
            }
        }
        const authtoken = jwt.sign(data, JWT_SECRET);
        res.json({authtoken});
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Internal Server Error");
    }
})

//Route 3 : Get logged in user detail using POST "/api/auth/getuser". Login Required
router.post('/getuser', fetchuser, async (req,res)=>{

    
    try {
        userId = req.user.id;
        const user = await User.findById(userId).select("-password");
        res.send(user);
    } catch (error) {
        console.error(error.message);
        res.status(500).send("Some error occurred");
    }

})
module.exports = router