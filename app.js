//jshint esversion:6
require('dotenv').config();
const express= require('express');
const bodyParser= require('body-parser');
const ejs= require('ejs');
const mongoose = require('mongoose');
// const encrypt= require('mongoose-encryption');
// const md5= require('md5');
// const bcrypt= require('bcrypt');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const app = express();
const port = 3000;
// const saltRounds = 11;



app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://127.0.0.1:27017/userDB",{useNewUrlParser: true});

const userSchema= new mongoose.Schema({
    email: String,
    password: String
});

userSchema.plugin(passportLocalMongoose);

const User= mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/",(req,res)=>{
    res.render("home");
})


app.get("/login",(req,res)=>{
    res.render("login");
});

app.get("/register",(req,res)=>{
    res.render("register");
});

app.get("/secrets",(req,res)=>{
    if(req.isAuthenticated()){
        res.render("secrets");
    }else{
        res.render("/login");
    }
});

app.get("/logout", (req,res)=>{
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});

app.post("/register",(req,res)=>{

    User.register({username: req.body.username}, req.body.password, function (err, user) {
      if(err){
        console.log(err);
        res.redirect('/register');
      }else{
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets");
        })
      }  
    })

   
});


app.post("/login",(req,res)=>{

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function (err) {
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })


})


app.listen(port,()=>{
    console.log(`listening on port${port}...`);
});