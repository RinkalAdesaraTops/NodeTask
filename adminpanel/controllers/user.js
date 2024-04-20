let registerModel = require('../models/registermodels');
let tokenModel = require('../models/tokenmodels');
const bcrypt = require('bcrypt');
const saltRounds = 10;

const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const secret_key = "secret1234";
var LocalStorage = require('node-localstorage').LocalStorage,
    localStorage = new LocalStorage('./scratch');

//Encrypting text
const encrypt_text = async (plainText, password) => {
    try {
        const iv = crypto.randomBytes(16);
        const key = crypto.createHash('sha256').update(password).digest('base64').substr(0, 32);
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);

        let encrypted = cipher.update(plainText);
        encrypted = Buffer.concat([encrypted, cipher.final()])
        return iv.toString('hex') + ':' + encrypted.toString('hex');

    } catch (error) {
        console.log(error);
    }
}
// Decrypting text
const decrypt_text = async (encryptedText, password) => {
    try {
        const textParts = encryptedText.split(':');
        const iv = Buffer.from(textParts.shift(), 'hex');

        const encryptedData = Buffer.from(textParts.join(':'), 'hex');
        const key = crypto.createHash('sha256').update(password).digest('base64').substr(0, 32);
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

        const decrypted = decipher.update(encryptedData);
        const decryptedText = Buffer.concat([decrypted, decipher.final()]);
        return decryptedText.toString();
    } catch (error) {
        console.log(error)
    }
}

const checkUser = async (req, res) => {
    if (req.cookies) {
        if (req.cookies.UserName === undefined || req.cookies.UserName === 'undefined') {
            res.clearCookie('UserName');
            res.redirect('/');
            return false;
        }
        return true;
    }
}



const getDashboard = async (req, res) => {

    var a = await checkUser(req, res);
    if (a === true) {
        res.render('index', { username: req.cookies.UserName, userimage: req.cookies.Userimage, selected: 'admin' });
    } else {
        res.render('index', { username: req.cookies.UserName, userimage: req.cookies.Userimage, selected: 'admin' })
    }
};





const getregister = async (req, res) => {
    res.render('register', {
        username: req.cookies.UserName,
        useremail: req.cookies.Useremail,
        userimage: req.cookies.Userimage,
        selected: 'register',
        message: req.flash('msg_category'),
        message_class: req.flash('msg_class'),
    })
}

const register = async (req, res) => {
    res.render('register', {
        username: req.cookies.UserName,
        useremail: req.cookies.Useremail,
        userimage: req.cookies.Userimage,
        selected: 'register',
        message: '',
        message_class: req.flash('msg_class'),
    })
}

const registerdata = async (req, res) => {

    // let isAllowToCreate = true;
    const { username, password, email, gender, qualification } = req.body;
    console.log(req.body);
    if (username, password, email) {
        
            const crypted = await bcrypt.hash(password, saltRounds)
            const res2 = new registerModel({
                id: 1,
                email: email,
                password: crypted,
                username: username,
                gender:gender,
                qualification:qualification,
                image:req.imgfilename,
                token: '',
                
            });
            

            await res2.save();

            var token = jwt.sign({ res2: res2 }, secret_key)
            console.log("generated token");
            console.log(token);
            let _id = res2._id;
            console.log(_id);
            const result = await registerModel.findByIdAndUpdate({ _id }, { $set: { token: token } })
            console.log(result);
            res.redirect('/login');

    

    } else {

        req.flash('msg_category', 'Please Enter All Fields');
        req.flash('msg_class', 'alert-success');

    }

}

const checkUserData = async (req, res) => {
    const dataUser = await registerModel.findOne({ email: req.body.email, password: req.body.password });
    if (dataUser) {
        res.cookie('UserName', dataUser.username);
        res.redirect('/admin');
    } else {
        req.flash('danger', 'Email or password wrong !!!');
        res.render('login', { message: req.flash('danger'), message_class: 'alert-danger' });
    }
}

const checkLogindata = async (req, res) => {
    let userdata = await registerModel.findOne({ email: req.body.email });
    
    if (req.body.email != '' && req.body.password != '') {
        if (!userdata) {
            req.flash('emsg_token', 'User not found');
            emsg_token = req.flash('emsg_token');
            res.render("login", { message: emsg_token, message_class: 'alert-danger'});
        } else {

            const isPasswordValid = await bcrypt.compare(req.body.password, userdata.password);

            if (!isPasswordValid) {
                req.flash('emsg_token', 'Invalid password');
                emsg_token = req.flash('emsg_token');
                res.render("login", { message: emsg_token, message_class: 'alert-danger'});
            } else {


                res.cookie('UserName', userdata.username);
                res.cookie('Useremail', userdata.email);
                res.cookie('Userimage', userdata.image);

                localStorage.setItem('userToken', JSON.stringify(userdata.token));
                
                res.redirect('/admin');
            }
        }

    } else {

        req.flash('emsg_token', 'Please Enter All Fields');
        emsg_token = req.flash('emsg_token');
        res.render("login", { message: emsg_token, message_class: 'alert-danger'});

    }

}



module.exports = {
    getDashboard,
    checkUserData,
    registerdata,
    register,
    getregister,
    checkLogindata,
}