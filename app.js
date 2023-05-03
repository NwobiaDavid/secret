//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
// const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook').Strategy;


const app = express();
const port = process.env.PORT || 3000;
// const saltRounds = 11;

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true });

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secrets: [String]
});

userSchema.plugin(passportLocalMongoose);

const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, {
      id: user.id,
      username: user.username,
      picture: user.picture,
    });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: 'https://secret-fkvw.onrender.com/auth/google/secrets',
      userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
    },
    async function (accessToken, refreshToken, profile, done) {
      try {
        // console.log(profile);
        // Find or create user in your database
        let user = await User.findOne({ googleId: profile.id });
        if (!user) {
          // Create new user in database
          const username =
            Array.isArray(profile.emails) && profile.emails.length > 0
              ? profile.emails[0].value.split('@')[0]
              : '';
          const newUser = new User({
            username: profile.displayName,
            googleId: profile.id,
          });
          user = await newUser.save();
        }
        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRETS,
      callbackURL: 'https://secret-fkvw.onrender.com/auth/facebook/secrets',
    },
    async function (accessToken, refreshToken, profile, done) {
        try {
         
          // Find or create user in your database
          let user = await User.findOne({ facebookId: profile.id });
          if (!user) {
            // Create new user in database
            const username =
              Array.isArray(profile.emails) && profile.emails.length > 0
                ? profile.emails[0].value.split('@')[0]
                : '';
            const newUser = new User({
              username: profile.displayName,
              facebookId: profile.id,
            });
            user = await newUser.save();
          }
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
  )
);

app.get('/', (req, res) => {
  res.render('home');
});

app.get(
  '/auth/facebook',
  passport.authenticate('facebook', { scope: ['public_profile'] })
);

app.get(
  '/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  }
);

app.get(
  '/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get(
  '/auth/google/secrets',
  passport.authenticate('google', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  }
);



app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.get('/secrets', (req, res) => {
 User.find({secrets: {$ne: null}})
 .then(foundUsers=>{
    res.render("secrets", {usersWithSecrets: foundUsers});
 })
 .catch((err)=>{console.log(err);})
});

app.get('/submit', (req, res) => {
  if (req.isAuthenticated()) {
    res.render('submit');
  } else {
    res.redirect('/login');
  }
});

app.get('/logout', (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect('/');
  });
});

app.post('/submit', (req, res) => {
  const submittedSecret = req.body.secret;
 
//   str = JSON.stringify(req.user, null, 4); 
//   console.log( str + "---id here " + submittedSecret + "---secret");

  User.findById(req.user.id)
    .then((foundUser) => {
        console.log(submittedSecret);
      foundUser.secrets.push(submittedSecret);
      foundUser.save()
      .then(()=>{
        res.redirect("/secrets");
      })
      .catch((err)=>{console.log(err);})
    })
    .catch((err) => {
      console.log(err);
    });
});

app.post('/register', (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect('/register');
      } else {
        passport.authenticate('local')(req, res, function () {
          res.redirect('/secrets');
        });
      }
    }
  );
});

app.post('/login', (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate('local')(req, res, function () {
        res.redirect('/secrets');
      });
    }
  });
});

app.listen(port, () => {
  console.log(`listening on port: ${port}...`);
});
