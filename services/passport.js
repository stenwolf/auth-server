const passport = require('passport');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');
const User = require('../models/user');
const config = require('../config');

//create local Strategy
//local strategy assume username by default, since using email => need to let it know
const localOptions = {userNameField: 'email'};
const localLogin = new LocalStrategy(localOptions, function(email, password, done){
  //verify email and password, call done with the user if correct email and password
  //otherwise call done with false
  User.findOne({email: email}, function(err, user){
    if(err){return done(err);}
    if(!user){return done(null, false);}

    //compare password
    user.comparePassword(password, function(err, isMatch){
      if(err){return done(err);}
      if(!isMatch){return done(null, false);}
      return done(null, user);
    });
  });
});

//setup jwt strategy
//1 - where to get jwt from, it could be anywhere, body, header, ...
//2 - tell where the secret key is
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

//create jwt Strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done){
  //see if userID in payload exists in DB
  //if yes, call done with that user
  //otherwise, call done without a user obj
  User.findBy(payload.sub, function(err, user){
    if(err){return done(err,false);}

    if(user){
      done(null, user); // no error, found user
    }
    else{
      done(null, false);//no error, couldnt find user
    }

  })
});

//tell passport to use jwtLogin
passport.use(jwtLogin);
passport.use(localLogin);
