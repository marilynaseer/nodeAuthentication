// config/passport.js

// load all the things we need
var LocalStrategy = require('passport-local').Strategy;

// load up the user model
var mysql = require('mysql');
var bcrypt = require('bcrypt-nodejs');
var dbconfig = require('./database');
var connection = mysql.createConnection(dbconfig.connection);

connection.query('USE ' + dbconfig.database);
// expose this function to our app using module.exports
module.exports = function(passport) {

	// =========================================================================
	// passport session setup ==================================================
	// =========================================================================
	// required for persistent login sessions
	// passport needs ability to serialize and unserialize users out of session

	// used to serialize the user for the session
	passport.serializeUser(function(user, done) {
		done(null, user.id);
	});

	// used to deserialize the user
	passport.deserializeUser(function(id, done) {
		connection.query("SELECT * FROM user WHERE id = ? ", [ id ], function(
				err, rows) {
			done(err, rows[0]);
		});
	});

	// =========================================================================
	// LOCAL SIGNUP ============================================================
	// =========================================================================
	// we are using named strategies since we have one for login and one for
	// signup
	// by default, if there was no name, it would just be called 'local'

	passport
			.use(
					'local-signup',
					new LocalStrategy(
							{
								// by default, local strategy uses username and
								// password, we will override with email
								usernameField : 'username',
								passwordField : 'password',
								passReqToCallback : true
							// allows us to pass back the entire request to the
							// callback
							},
							function(req, username, password, done) {
								// find a user whose email is the same as the
								// forms email
								// we are checking to see if the user trying to
								// login already exists
								connection
										.query(
												"SELECT * FROM user WHERE username = ?",
												[ username ],
												function(err, rows) {
													if (err)
														return done(err);
													if (rows.length) {
														return done(
																null,
																false,
																req
																		.flash(
																				'signupMessage',
																				'That username is already taken.'));
													} else {
														// if there is no user
														// with that username
														// create the user
														var hashed='Y';
															
														var newUserMysql = {
															username : username,
															password : bcrypt
																	.hashSync(
																			password,
																			null,
																			null),
															hashed:hashed
														// use the generateHash
														// function in our user
														// model
														};

														var insertQuery = "INSERT INTO user ( username, password,hashed ) values (?,?,?)";

														connection
																.query(
																		insertQuery,
																		[
																				newUserMysql.username,
																				newUserMysql.password ,
																				newUserMysql.hashed],
																		function(
																				err,
																				rows) {
																			if(err){
																				throw err;
																			}
																			console
																					.log("++++++++++"
																							+ rows);
																			newUserMysql.id = rows.insertId;

																			return done(
																					null,
																					newUserMysql);
																		});
													}
												});
							}));

	// =========================================================================
	// LOCAL LOGIN =============================================================
	// =========================================================================
	// we are using named strategies since we have one for login and one for
	// signup
	// by default, if there was no name, it would just be called 'local'
	passport.use('local-login', new LocalStrategy({
		// by default, local strategy uses username and password, we will
		// override with email
		usernameField : 'username',
		passwordField : 'password',
		passReqToCallback : true
	// allows us to pass back the entire request to the callback
	}, function(req, username, password, done) { // callback with email and
													// password from our form
		connection.query("SELECT * FROM user WHERE username = ?", [ username ],
				function(err, rows) {
					if (err)
						return done(err);
					if (!rows.length) {
						return done(null, false, req.flash('loginMessage',
								'No user found.')); // req.flash is the way to
													// set flashdata using
													// connect-flash
					}
					
					

					var salt = bcrypt.genSaltSync(10);
					// Hash the password with the salt
					var hash = bcrypt.hashSync(rows[0].password, salt);
					console.log(rows[0].password);
//					console.log(hash);
					console.log("---" + password);
					/*var hash1 = bcrypt.hashSync(password, salt);
					console.log("--=====" + hash1);*/
					/*
					 var hash; // Hash the password with the salt
					  bcrypt.hash(rows[0].password, 10, function(err, hash) {
					  if (err) { throw (err);
					   } hash=hash }); var hash1; 
					   // Hash the password with the
					 
					  bcrypt.hash(password, 10, function(err, hash) { if
					  (err) { throw (err);
					   } hash1=hash; });
					 */
					console.log(rows[0].hashed);
					if(rows[0].hashed=='Y'){
					bcrypt.compare(password, rows[0].password, function(err, result) {
						console.log("Async1: " + result) // returns true!
						if (!result)
							return done(null, false, req.flash('loginMessage',
									'Oops! Wrong password.'));
						else
							return done(null, rows[0]);

					});
					}
					else{
						bcrypt.compare(password, hash, function(err, result) {
							console.log("Async2: " + result) // returns true!
							if (!result)
								return done(null, false, req.flash('loginMessage',
										'Oops! Wrong password.'));
							else
								return done(null, rows[0]);

						});
					}

					// if the user is found but the password is wrong
					/*
					 * if (!bcrypt.compareSync(password, rows[0].password))
					 * return done(null, false, req.flash('loginMessage', 'Oops!
					 * Wrong password.'));
					 */
					// create the loginMessage and save it to session as
					// flashdata
					// all is well, return successful user
				});
	}));
};
/*
 * passport.use('local-login', new LocalStrategy({ // by default, local strategy
 * uses username and password, we will // override with email usernameField :
 * 'username', passwordField : 'password', passReqToCallback : true // allows us
 * to pass back the entire request to the callback }, function(req, username,
 * password, done) { // callback with email and // password from our form
 * connection.query("SELECT * FROM user WHERE username = ?", [ username ],
 * function(err, rows) { if (err) return done(err); if (!rows.length) { return
 * done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash
 * is the way to // set flashdata using // connect-flash }
 * 
 * var salt = bcrypt.genSaltSync(10); // Hash the password with the salt var
 * hash = bcrypt.hashSync(rows[0].password, salt);
 * console.log(rows[0].password); console.log(hash);
 * console.log("---"+password);
 * 
 * var hash; // Hash the password with the salt bcrypt.hash(rows[0].password,
 * 10, function(err, hash) { if (err) { throw (err); hash1=hash; } var hash1; //
 * Hash the password with the salt bcrypt.hash(password, 10, function(err, hash) {
 * if (err) { throw (err); hash1=hash; }
 *  // if the user is found but the password is wrong bcrypt.compare(hash1,
 * hash, function(err, result) { console.log("Async: "+result) // returns true! })
 * 
 * if (bcrypt.compareSync(hash1, hash)) return done(null, false,
 * req.flash('loginMessage', 'Oops! Wrong password.'));
 *  // create the loginMessage and save it to session as // flashdata
 * 
 * 
 * 
 * bcrypt.compare('mypassword', hash, function(err, result) { if (err) { throw
 * (err); } console.log(result); }); }); // all is well, return successful user
 * return done(null, rows[0]); }); })); };
 */
