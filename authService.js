const express = require("express");
const jwt = require('jsonwebtoken');
const sqlite = require('sqlite3');
const crypto = require('crypto');
const { query } = require("express");

var authService = express();

//To change to a more secure version
const KEY = "secret key";

var db = new sqlite.Database("users.sqlite3");

db.run(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL,
  password TEXT NOT NULL
)`);

authService.post('/signup', express.urlencoded(),function(req, res) {
  var password = crypto.createHash('sha256').update(req.body.password).digest('hex');
  db.get("SELECT FROM users WHERE username = ?", [req.body.username], function(err, row) {
    if(row != undefined ) {
      console.error("can't create user " + req.body.username);
      res.status(409);
    res.send("A user with that username already exists");
    } else {
      console.log("Can create user " + req.body.username);
      db.run('INSERT INTO users(username, password) VALUES (?, ?)', [req.body.username, password]);
      res.status(201);
      res.send("Success");
    }
  });
});

authService.post('/signin', express.urlencoded(),function(req, res) {
  console.log(req.body.username + " attempted login");
  var password = crypto.createHash('sha256').update(req.body.password).digest('hex');
  db.get("SELECT * FROM users WHERE (username, password) = (?, ?)", [req.body.username, password], function(err, row) {
    if(row != undefined ) {
      var payload = {
        username: req.body.username,
      };

      var token = jwt.sign(payload, KEY, {algorithm: 'HS256', expiresIn: "15d"});
      console.log("Success");
      res.send(token);
    } else {
      console.error("Failure");
      res.status(401)
      res.send("There's no user matching that");
    }
  });
});

authService.get('/verify', function(req, res) {
  console.log("Received request for verification from "+req.query.username);
  console.log(req.query.jwt);
  var str = req.query.jwt;
  try {
    jwt.verify(str, KEY, {algorithm: 'HS256'});
    console.log("Good Token");
    res.send("Good Token");
  } catch {
    res.status(401);
    console.log("Bad Token");
    res.send("Bad Token");
  }
});

authService.listen(3000, function () {
    return console.log("Started user authentication server listening on port 3000");
});