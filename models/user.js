const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

//define model
const userSchema = new Schema({
  email: {type: String, unique: true, lowercase: true},
  password: String
});

//On save hook, encrypt password
userSchema.pre('save', function(next){
  const user = this;

  //generate salt, then run call back
  bcrypt.genSalt(10, function(err, salt){
    if(err){return next(err);}

    //hash password using salt
    bcrypt.hash(user.password, salt, null, function(err, hash){
      if(err){return next(err);}

      //overwrite plain text password with encrypted password
      user.password = hash;
      next();
    });
  });
})

userSchema.methods.comparePassword = function(candidatePwd, callback){
  bcrypt.compare(candidatePwd, this.password, function(err, isMatch){
    if(err){return callback(err);}
    callback(null, isMatch);
  });
}

//create model class
const ModelClass = mongoose.model('user', userSchema);

//export model
module.exports = ModelClass;
