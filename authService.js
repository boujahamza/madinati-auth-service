const express = require("express");
const jwt = require('jsonwebtoken');
const sqlite = require('sqlite3');
const crypto = require('crypto');

var authService = express();

//To change to a more secure version
const KEY = "secret key";

var MongoClient = require('mongodb').MongoClient;
var url = "mongodb+srv://admin:admin@cluster0.uf5pu.mongodb.net/AuthServiceDB?retryWrites=true&w=majority";

let dbConnection;

MongoClient.connect(url,function (err, db) {
    if (err) throw err;

    dbConnection = db.db("AuthServiceDB");
    console.log("Successfully connected to MongoDB.");
});

authService.post('/signup', express.urlencoded(),function(req, res) {
  var password = crypto.createHash('sha256').update(req.body.password).digest('hex');
  var alreadyExists = false;
  dbConnection
        .collection("users")
        .find({username:req.body.username}).toArray(function (err, result) {
            if (result.length) {
              res.status(409);
              res.send("A user with that username already exists");
              alreadyExists = true;
           } else {
            console.log("Can create user " + req.body.username);
            }
          });
  if(!alreadyExists){
    dbConnection.collection("users").insertOne({'username':req.body.username, 'password':password},function (err, result) {
      if (err) {
      res.status(400).send("Error");
      } else {
        res.status(201);
        res.send("Success");
      }
    })
  }
          
});

authService.post('/signin', express.urlencoded(),function(req, res) {
  console.log(req.body.username + " attempted login");
  var password = crypto.createHash('sha256').update(req.body.password).digest('hex');
  dbConnection.collection("users")
        .find({username:req.body.username,password:password}).toArray(function (err, result) {
            if (result.length) {
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