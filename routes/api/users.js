const express = require("express");
const router = express.Router();
const gravatar = require("gravatar");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("config");
const { check, validationResult } = require("express-validator");

const User = require("../../models/User");

// @route   Post api/users
// @desc    Register User
// @access  Public
router.post(
  "/",
  [
    check("name", "Name is required").not().isEmpty(),
    check("email", "Please enter a valid email").isEmail(),
    check(
      "password",
      "Please enter a password with 6 or more characters"
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() }); // 400 is bad request
    }

    const { name, email, password } = req.body; // destructs request so its easier to call
    try {
      //See if user exists
      let user = await User.findOne({ email });
      if (user) {
        res.status(400).json({ errors: [{ msg: "User already exits" }] });
      }
      // Get users gravatar
      const avatar = gravatar.url(email, {
        s: "200", // size
        r: "pg", //rating
        d: "mm", // default avatar
      });

      user = new User({
        name,
        email,
        avatar,
        password,
      });
      // Encrypt password
      const salt = await bcrypt.genSalt(10); // 10 rounds recommended by bcrpyt
      user.password = await bcrypt.hash(password, salt);
      await user.save();

      // Return jsonwebtobken
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get("jwtToken"),
        { expiresIn: 360000 }, //3600 recommended for production
        (err, token) => {
          if (err) throw err;
          res.json({ token }); //else
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(500).send("Server error");
    }
  }
);

module.exports = router;
