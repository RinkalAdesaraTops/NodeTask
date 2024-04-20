const express = require('express');
const body = require('body-parser');
const bodyParser = body.urlencoded({ extended: false });
const mongoose = require('mongoose');
var LocalStorage = require('node-localstorage').LocalStorage,
localStorage = new LocalStorage('./scratch');
const maindata =  async ()=>{
    const url = "mongodb://127.0.0.1:27017/adminpanel";
    await mongoose.connect(url);
    console.log('established connection');  
}
maindata();
const passport = require('passport');
const router = express.Router();

const multer = require("multer");
let imgfilename = '';
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
         cb(null, "./upload/");    
    },
    filename: function (req, file, cb) {
        const originalName = file.originalname;
        const extension = originalName.split('.').pop();
        
        const uniqueFilename = Date.now() + '-' + originalName;
        req.imgfilename = uniqueFilename;
        // imgfilename = Date.now() + file.originalname;
         cb(null, uniqueFilename);
    }
});
const upload = multer({ storage: storage });

const { getDashboard, registerdata,checkLogindata,register,getregister} = require("../controllers/user");

const verifyToken = require('../models/jwtconfing');



router.get('/admin', getDashboard);

router.get('/register',register);
router.get('/getregister',getregister);
router.post('/register', upload.single('image'), registerdata);

router.post("/login",bodyParser,checkLogindata);


module.exports = router;
