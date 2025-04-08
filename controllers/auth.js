const express = require("express");
const router = express.Router();
const User = require("../models/user.js");
const bcrypt = require("bcrypt");


router.get("/sign-up", (req, res) => {
    res.render("auth/sign-up.ejs");
  });

router.post("/sign-up", async (req, res) => {
    const userInDatabase = await User.findOne({ username: req.body.username });
    if (userInDatabase) {
        return res.status(406).send("Username already taken.");
    }
    if (req.body.password !== req.body.confirmPassword) {
        return res.status(406).send("Password and Confirm Password fields must match");
      }
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);
    req.body.password = hashedPassword;
    // Create a new user in the database
    const user = await User.create(req.body);
    res.send(`Thanks for signing up ${user.username}`);
    
    
  });
// Sign-in route
router.get("/sign-in", (req, res) => {
    res.render("auth/sign-in.ejs");
  }
);

router.post("/sign-in", async (req, res) => {
    const userInDatabase = await User.findOne({ username: req.body.username });

    //does user exist?
    //if not, throw error
    if(!userInDatabase) {
        return res.status(401).send("Login Failed.");
    }
    //does password match?
    //if not, throw error
    const validPassword = bcrypt.compareSync(
        req.body.password, 
        userInDatabase.password
    );
    if(!validPassword) {
        return res.status(401).send("Login Failed.");
    }
  // There is a user AND they had the correct password. Time to make a session!
  // Avoid storing the password, even in hashed format, in the session
  // If there is other data you want to save to `req.session.user`, do so here!
  req.session.user = {
    username: userInDatabase.username,
    _id: userInDatabase._id
  };

  res.redirect("/");
});

router.get("/sign-out", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});



module.exports = router;