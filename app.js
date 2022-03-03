//jshint esversion:6
//require env package
require('dotenv').config();
//npm framework
const express = require("express");
//translate html to json
const bodyParser = require("body-parser");
//template
const ejs = require("ejs");
// Object Data Modeling (ODM) library for MongoDB
const mongoose = require("mongoose");
//set the needed cookie for specified session
const session = require('cookie-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//activate the express package
const app = express();
//load the html and css
app.use(express.static("public"));
//use the ejs package to load ejs templates
app.set('view engine', 'ejs');
//use bodyParser middle ware
app.use(bodyParser.urlencoded({
  extended: true
}));

//Remember the position of below app.use session code is important
//initialize a middleware with app.use, pass it the session variable
//this middleware will file every consequte request from server
app.use(session({ //this session receives object
  secret: "Our little secret.", //the key that signs the cookie
  //and this cookie will sign our cookie that is saved in our browser
  resave: false, //we don't want browser save every request
  saveUninitialized: false //if we didn't touch or modified the seesion, then we don't want it save
}));
//tell the app to initialize the passport and initialize passport package
app.use(passport.initialize());
app.use(passport.session());
//connect mongodb
mongoose.connect("mongodb+srv://" + process.env.ATLAS_USER + ":" + process.env.ATLAS_PWD + "@cluster0.jyonr.mongodb.net/userDB");
// mongoose.set("useCreateIndex", true);

//mongoose Schema
//in order the schema to have a plugin, it has to be a mongoose Schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//add plugin
//to hash and salt in our password and users into our MongoDB databse
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//new mongoose model
const User = new mongoose.model("User", userSchema);


passport.use(User.createStrategy());
//serialize and deserialize is only used when in session
//serialize means pack the cookie, deserialize means unpack the cookie
//works with mulitiple authentication
passport.serializeUser(function(user, done) {
  done(null, user.id);
})
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
//OAuth protocals
//the position to place codes matters
//must put behind the session to let the cookie store login info
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-annabelle-sun.herokuapp.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" //to retreive the user info not from Google+ as it will be deprecated
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ //from mongoose findOrCreate message
      googleId: profile.id,
      username: profile.emails[0].value
    }, function(err, user) {
      return cb(err, user);
    });
  }
));


app.get("/", function(req, res) {
  res.render("home");
})

app.get("/auth/google",
  //route specific middleware
  passport.authenticate('google', {
    scope: ["profile", 'email']
  })
);
//use passport to authenticate users with a new google strategy
app.get("/auth/google/secrets",
  passport.authenticate('google', {
    failureRedirect: "/login"
  }),
  function(req, res) {
    //Successful authentication,redirect to secrets
    res.redirect("/secrets");
  }
);

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({
    "secrets": {
      $ne: null //not null in secrets collections
    }
  }, function(err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {
          usersWithSecrets: foundUsers
        });
      }
    }
  });
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;
  //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);
  User.findById(req.user.id, function(err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });

});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
})

app.post("/register", function(req, res) {
  User.register({ //comes from passport-local-mongoose package
    username: req.body.username
  }, req.body.password, function(err, user) {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/login", function(req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });
  //this method comes from passport
  req.login(user, function(err) {
    if (err) {
      console.log(err);
    } else {
      //The local authentication strategy authenticates users using a username and password.
      //The strategy requires a verify callback, which accepts these credentials and calls done providing a user.
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});





app.listen(3000 || process.env.PORT, function() {
  console.log("Server started on port 3000.");
});