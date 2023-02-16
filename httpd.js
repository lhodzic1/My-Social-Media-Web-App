const express = require("express");
var mustacheExpress = require("mustache-express");
const app = express();
var session = require("express-session");
const fs = require("fs");
var https = require("https");
var cookie = require("cookie");
const crypto = require("crypto");
var safe = require("safe-regex");
const MongoClient = require("mongodb").MongoClient;

const options = {
  key: fs.readFileSync("./cert/server.key"),
  cert: fs.readFileSync("./cert/server.crt"),
};

//keys for decripting the cookie signature
let signature_keys = [];

//serving static files
app.use(express.static("public"));
//mustache view engine
app.set("view engine", "mustache");
app.engine("mustache", mustacheExpress());
app.set("views", __dirname + "/templates");

//middleware for receiving json encoded body
app.use(express.json());
//middleware for receiving urlencoded body
app.use(express.urlencoded({ extended: false }));

//session middleware
app.use(session({ secret: "secret" }));

//cookie helper function - calculates the expiration time
function getCookieExpiration() {
  //cookie expired in 30 minutes
  var expireTime = 30 * 60000;
  return expireTime;
}

//cookie helper function - checks whether the session id is valid
async function checkCookie(req) {
  //no cookie header
  if (!req.headers.cookie) return false;

  var cookies = cookie.parse(req.headers.cookie);

  if (cookies["squeak-session"] == undefined) return false;

  var json = JSON.parse(cookies["squeak-session"]);

  var sessionid = json["sessionid"].toString().normalize();

  //Basic Multilingual Plane charachter category check
  const regexpBMPWord = /([\u0000-\u0019\u0021-\uFFFF])+/u;
  if (!regexpBMPWord.test(sessionid)) return false;

  //check whether the session identifier is valid
  let session = await findSession(sessionid);
  if (session === null) return false;

  //verifying the digital signature
  //recreating the buffer
  const myBuffer = Buffer.from(json["signature"], "base64");

  //retrieving the public key
  let publicKey = null;

  for (let i = 0; i < signature_keys.length; i++)
    if (json["sessionid"] === signature_keys[i].sessionid.toString()) {
      publicKey = signature_keys[i].key;
      break;
    }

  //no key for this session
  if (!publicKey) return false;

  //verifying the signature
  const isVerified = crypto.verify(
    "sha256",
    Buffer.from(getCookieUsername(req)),
    {
      key: publicKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    },
    myBuffer
  );

  return isVerified;
}

//helper function for getting username from cookie
function getCookieUsername(req) {
  var cookies = cookie.parse(req.headers.cookie);
  return JSON.parse(cookies["squeak-session"]).username;
}

//GET /
app.get("/", async function (req, res) {
  //checking the session cookie
  //if the user is not logged in - the login page is presented
  if (!(await checkCookie(req))) {
    // rendering the login page
    res.render("login");
    return;
  }

  //generating the CSRF token
  if (req.session.csrf === undefined) {
    req.session.csrf = crypto.randomBytes(128).toString("base64"); // convert random data to a string
  }

  const username = getCookieUsername(req);

  //rendering the main page
  Promise.all([getUsernames(), getSqueaks("all"), getSqueaks(username)]).then(
    (results) => {
      res.render("index", {
        current_user: username,
        users: results[0],
        token: req.session.csrf,
        squeaks: results[1],
        squeals: results[2],
      });
    }
  );
});

//POST signin
app.post("/signin", async function (req, res) {
  //fetching username and password
  const username = req.body.username.toString().normalize();
  const password = req.body.password.toString().normalize();

  let login = false;

  //Basic Multilingual Plane charachter category check
  const regexpBMPWord = /([\u0000-\u0019\u0021-\uFFFF])+/u;

  if (regexpBMPWord.test(username) && regexpBMPWord.test(password))
    login = await authenticate(username, password);

  //successful login
  if (login) {
    //creating new session identifier
    const sessionid = await newSession();

    //generating public and private keys
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });

    signature_keys.push({ sessionid: sessionid, key: publicKey });

    //creating the signature from username
    const signature = crypto.sign("sha256", Buffer.from(username), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });

    //wiriting response
    res.cookie(
      "squeak-session",
      JSON.stringify({
        sessionid: sessionid,
        username: username,
        signature: signature.toString("base64"),
      }),
      {
        maxAge: getCookieExpiration(),
        httpOnly: true,
        secure: true,
      }
    );
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(true));
  }
  //unsuccessful login
  else {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(false));
    return;
  }
});

//POST signup
app.post("/signup", async function (req, res) {
  //fetching username and password
  const username = req.body.username.toString().normalize();
  const password = req.body.password.toString().normalize();

  //check username length
  let validUsername = username !== undefined && username.length >= 4;

  //check password length
  let validPassword = password !== undefined && password.length >= 8;

  //check whether username is safe against ReDoS attacks
  if (!safe(username)) {
    validUsername = false;
  }

  //Basic Multilingual Plane charachter category check
  const regexpBMPWord = /([\u0000-\u0019\u0021-\uFFFF])+/u;
  if (!regexpBMPWord.test(username)) validUsername = false;
  if (!regexpBMPWord.test(password)) validPassword = false;

  //check if the username is already taken
  if (validUsername && (await checkUsername(username))) {
    validUsername = false;
  }

  //check whether password contains username
  if (validUsername && validPassword) {
    let nameregex = new RegExp(username);
    validPassword &= !nameregex.test(password);
  }

  //creating response
  let success = false;
  let reason;

  if (validUsername && validPassword) {
    success = true;
  } else if (!validUsername) {
    reason = "username";
  } else {
    reason = "password";
  }

  //sucessful signup
  if (success) {
    
    //storing user in database
    addUser(username, password);

    //creating a new session identifier
    const sessionid = await newSession();

    //generating public and private keys
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });

    signature_keys.push({ sessionid: sessionid, key: publicKey });

    //creating the signature from username
    const signature = crypto.sign("sha256", Buffer.from(username), {
      key: privateKey,
      padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
    });

    //wiriting response
    res.cookie(
      "squeak-session",
      JSON.stringify({
        sessionid: sessionid,
        username: username,
        signature: signature.toString("base64"),
      }),
      {
        maxAge: getCookieExpiration(),
        httpOnly: true,
        secure: true,
      }
    );
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
  }
  //unsuccessful signup
  else {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: success, reason: reason }));
  }
});

//POST signout
app.post("/signout", async function (req, res) {
  //checking the session cookie
  //if the user is not logged in - he can't sign out
  if (!checkCookie(req)) {
    res.writeHead(400, { "Content-Type": "text/plain" });
    res.end("Not logged in!");
    return;
  }

  //removing the session identifier from valid identifiers
  var cookies = cookie.parse(req.headers.cookie);
  var json = JSON.parse(cookies["squeak-session"]);

  await invalidateSession(json["sessionid"]);

  //deleting the assigned public key
  for (let i = 0; i < signature_keys.length; i++)
    if (json["sessionid"] === signature_keys[i].sessionid.toString()) {
      signature_keys.splice(i, 1);
      break;
    }

  res.writeHead(200);
  res.end(JSON.stringify(true));
});

//POST squeak
app.post("/squeak", async function (req, res) {
  //checking the session cookie
  //if no valid session id is presented, server ends the request without saving the squeak
  if (!checkCookie(req)) {
    res.end();
    return;
  }

  //checking the CSRF token
  //if no valid CSRF is presented, server drops the squeak
  if (!req.body.csrf || req.body.csrf !== req.session.csrf) {
    res.end();
    return;
  }

  //creating a new squeak
  await addSqueak(getCookieUsername(req), req.body.recipient, req.body.squeak);

  res.writeHead(302, { Location: "/" });
  res.end();
});

//database setup
// Connection URL
const url = "mongodb://localhost:27017";

// Use connect method to connect to the Server
MongoClient.connect(url)
  .then((cluster) => {
    mongoCluster = cluster;

    let db = cluster.db("Squeak!");
    squeaks = db.collection("squeaks");
    credentials = db.collection("credentials");
    sessions = db.collection("sessions");

    let server = https.createServer(options, app);
    server.listen(8000);
  })
  .catch((error) => {
    console.log(error);
  });

async function authenticate(username, password) {
  let user = await credentials.findOne({
    username: username,
    password: password,
  });
  return user !== null;
}

async function addUser(username, password) {
  await credentials.insertOne({ username: username, password: password });
}

async function checkUsername(username) {
  let user = await credentials.findOne({
    username: username,
  });
  return user !== null;
}

async function getUsernames() {
  let users = await credentials.find().toArray();
  return users.map((user) => {
    let temp = {};
    temp["username"] = user.username;
    return temp;
  });
}

async function findSession(sessionid) {
  return await sessions.findOne({ id: sessionid });
}

async function newSession() {
  let sessionid = crypto.randomBytes(64).toString("hex");
  await sessions.insertOne({ id: sessionid });
  return sessionid;
}

async function invalidateSession(sessionid) {
  return await sessions.findOneAndDelete({ id: sessionid });
}

async function addSqueak(username, recipient, squeak) {
  let options = { weekday: "short", hour: "numeric", minute: "numeric" };
  let time = new Date().toLocaleDateString("sv-SE", options);
  await squeaks.insertOne({
    name: username,
    time: time,
    recipient: recipient,
    squeak: squeak,
  });
}

async function getSqueaks(recipient) {
  return await squeaks.find({ recipient: recipient }).toArray();
}
