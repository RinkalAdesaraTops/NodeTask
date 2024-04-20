const jwt = require('jsonwebtoken');
var LocalStorage = require('node-localstorage').LocalStorage,
    localStorage = new LocalStorage('./scratch');
const secretkey = 'secret1234';
const verifyToken = (req, res, next) => {
    let t = localStorage.getItem('userToken');
    if (t != 'undefined') {
        let token = JSON.parse(t);
        jwt.verify(token, secretkey, function (err, decoded) {
            if (err) {
                console.log(err);
                res.redirect('/')
            } else {
                next();
            }
        });
    } else {
        res.redirect('/')
    }

}

module.exports = verifyToken;