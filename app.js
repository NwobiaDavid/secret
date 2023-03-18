//jshint esversion:6
require('dotenv').config();
const express= require('express');
const bodyParser= require('body-parser');
const ejs= require('ejs');
const mongoose = require('mongoose');
// const encrypt= require('mongoose-encryption');
// const md5= require('md5');
const bcrypt= require('bcrypt');

const app = express();
const port = 3000;
const saltRounds = 11;



app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://127.0.0.1:27017/userDB",{useNewUrlParser: true});

const userSchema= new mongoose.Schema({
    email: String,
    password: String
});

// const secret= process.env.SECRET;
// userSchema.plugin(encrypt, { secret: secret,encryptedFields: ['password'] });

const User= mongoose.model("User", userSchema);

app.get("/",(req,res)=>{
    res.render("home");
})


app.get("/login",(req,res)=>{
    res.render("login");
});

app.get("/register",(req,res)=>{
    res.render("register");
});

app.post("/register",(req,res)=>{

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser= new User({
            email: req.body.username,
            password: hash
        });
    
        newUser.save()
        .then(()=>{
            res.render("secrets");
        })
        .catch((err)=>{console.log(err);});
    });
   
});


app.post("/login",(req,res)=>{
    const username= req.body.username;
    const password= req.body.password;

    User.findOne({email: username})
    .then(foundUser=>{
        bcrypt.compare(password, foundUser.password, function(err, result) {
           if(result === true){
            res.render("secrets");
           }
        });
    })
    .catch(err=>{console.log(err);});
})


app.listen(port,()=>{
    console.log(`listening on port${port}...`);
});