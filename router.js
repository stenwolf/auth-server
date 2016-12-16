const Authentication = require('./controllers/authentication');
const passportService = require('./services/passport');
const passport = require('passport');
//default passport create a session cookie, since using token, dont want session
const requireAuth = passport.authenticate('jwt', {session: false});
const requireSignin = passport.authenticate('local', {session: false});
module.exports = function(app){
  app.get('/', requireAuth, function(req, res){
    res.send({hi: 'there'});
  });
  app.post('/signin', requireSignin, Authentication.signin);
  app.post('/signup', Authentication.signup);
}
