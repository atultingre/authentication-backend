// config/passport.js
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const bcrypt = require("bcrypt");
const User = require("../models/User");

module.exports = function (passport) {
  passport.use(
    // Local Strategy
    new LocalStrategy(
      {
        usernameField: "emailOrPhone",
        passwordField: "password",
      },
      async (emailOrPhone, password, done) => {
        try {
          const user = await User.findOne({
            $or: [{ email: emailOrPhone }, { phone: emailOrPhone }],
          });

          if (!user) {
            return done(null, false, {
              message: "Invalid email or phone number",
            });
          }

          const isMatch = await bcrypt.compare(password, user.password);

          if (!isMatch) {
            return done(null, false, { message: "Invalid password" });
          }

          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  passport.use(
    // JWT Strategy
    new JwtStrategy(
      {
        jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
        secretOrKey: process.env.JWT_SECRET_KEY,
      },
      (jwtPayload, done) => {
        return done(null, jwtPayload);
      }
    )
  );
};
