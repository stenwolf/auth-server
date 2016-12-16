const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user){
  const timestamp = new Date().getTime();
  //sub = subject, iat = issued at time
  return jwt.encode({sub: user.id, iat: timestamp}, config.secret);
}

exports.signin = function(req, res, next){
  //user already have authentication, just give token
  res.send({token: tokenForUser(req.user)});
}

exports.signup = function(req, res, next){
  const email = req.body.email;
  const password = req.body.password;

  if(!email || !password){
    return res.status(422).send({error: 'You must provide email and password'});
  }

  //see if email exist
  //find one, then callback
  User.findOne({email: email}, function(err, result){
    if(err){return next(err)};//in case connection failed or so

    //if email already exists
    if(result){
      return res.status(422).send({error: 'Email is already in use'});;//422 = un-processable entity
    }

    //create and save user record
    const user = new User({
      email: email,
      password: password
    });
    user.save(function(err){
      if(err){return next(err);}
      res.json({token: tokenForUser(user)});
    });
  });
}
