import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";
import fs from "fs";
import path from "path";
import https from "https";



///////////////////////////

const app = express();
const port = 3000;
const saltRounds = 10; //security level of hashing
env.config();//keep session passwords secret
app.use((req, res, next) => {
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  next();
});
app.use(express.static("public"));
app.use('/game', express.static( 'game', {
  setHeaders: (res) => {
      res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
      res.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
  }
}));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(bodyParser.urlencoded({ extended: true }));


app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();




app.get("/", async (req, res) => {
  try {
    let secretsData = []; // Array to store username and secret pairs

    // Fetch all usernames and secrets from the database
    const result = await db.query("SELECT username, secret FROM users");

    if (result.rows.length > 0) {
      secretsData = result.rows; // Store all rows containing usernames and secrets
    }

    // Render the data in the EJS template
    res.render("index.ejs", { secretsData: secretsData });
  } catch (err) {
    console.log(err);
    res.status(500).send("An error occurred.");
  }
});






app.get("/about",(req,res)=>{
  res.render("about.ejs");
});
app.get("/patches", (req,res)=>{
  res.render("patches.ejs");
});

app.get("/account", (req,res)=>{

  if(req.isAuthenticated()){
    res.render("account.ejs",  { username: req.user.username });
  }else{
    res.redirect("/login");
  };

  
});

app.get("/game", (req,res)=>{

  if(req.isAuthenticated()){
    res.render("game.ejs");
  }else{
    res.redirect("/login");
  };
});



app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/account",
  passport.authenticate("google", {
    successRedirect: "/account",
    failureRedirect: "/login",
  })
);

app.get("/login", (req,res)=>{
  if(req.isAuthenticated()){
    res.redirect("/account");
  }else{
    res.render("./partials/login.ejs");
  };
  

});app.get("/register", (req,res)=>{
  res.render("./partials/register.ejs");

});



app.get("/logout", (req,res)=>{
  req.logout((err)=>{
    if(err){
      console.log(err);
    }else{
      res.redirect("/");
    }
  })
})

app.post("/account", async(req,res)=>{
  const secret = req.body.secret;
  console.log(req.user);

  try{
    await db.query("UPDATE users SET secret =$1 WHERE email =$2", [secret, req.user.email,]);
    res.redirect("/");
  }catch(err){
    console.log(err);
  }
})

app.post("/login", passport.authenticate("local", {
  successRedirect:"/account",
  failureRedirect:"/login",
}));

app.post("/register", async (req, res) => {
  const email = req.body.username; // Assuming the form field name is 'username'
  const password = req.body.password; // Assuming the form field name is 'password'
  const username = req.body.nickname; // Assuming the form field name is 'nickname'

  try {
    // Check if the email already exists
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      // Email already exists, render with an error
      res.render("./partials/register.ejs", {
        error: "Email already in use. Try logging in.",
      });
    } else {
      // Hash the password
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error during hashing", err);
          res.render("./partials/register.ejs", {
            error: "An error occurred. Please try again.",
          });
        } else {
          // Insert the new user into the database
          const result = await db.query(
            "INSERT INTO users (email, password, username) VALUES ($1, $2, $3) RETURNING *",
            [email, hash, username]
          );
          const user = result.rows[0];
          req.login(user, (err)=>{
            console.log(err);
            res.redirect("/account")
          });
          console.log("User registered:", result);
        }
      });
    }
  } catch (err) {
    console.error("Database error:", err);
    res.render("./partials/register.ejs", {
      error: "An unexpected error occurred. Please try again.",
    });
  }
});

passport.use(new Strategy(async function verify(username, password,cb){
  console.log(username);
  try{
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1",[
      username,
    ]);
    if(checkResult.rows.length >0 ){
      const user = checkResult.rows[0];
      const storedHashedPassword = user.password;


      bcrypt.compare(password, storedHashedPassword, (err,result)=>{
        if(err){
          return cb(err);
        }else{
          if(result){
            return cb(null, user);
          }else{
            return cb(null, false);
          }
        }
      });
    }else{
      return cb("User not found");
    }} catch(err){
      return cb(err);
    }
})
);

passport.use("google", new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/account",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
}, async(accesToken, refreshToken, profile, cb)=>{
  console.log(profile);
  try{
    const result = await db.query("SELECT * FROM users WHERE email = $1 ", [profile.email])
    if (result.rows.length===0){
      const newUser = await db.query("INSERT INTO users (email, password, username) VALUES ($1, $2, $3)", [profile.email, "google", profile.email])
      cb(null, newUser.rows[0]);
    }else{
      cb(null, result.rows[0])
    }
  }catch(err){
    cb(err);
  }
}))

passport.serializeUser((user,cb)=>{
  cb(null, user);

});
passport.deserializeUser((user,cb)=>{
  cb(null, user);
  
});
// app.listen(port, () => {
//   console.log(`Server running on  http://localhost:${port}/`);
// });

// HTTPS server options
const httpsOptions = {
  key: fs.readFileSync('cert.key'),
  cert: fs.readFileSync('cert.crt')
};

// Create HTTPS server
https.createServer(httpsOptions, app).listen(3000, () => {
  console.log('HTTPS server running on https://localhost:3000');
  console.log('Access the game at https://localhost:3000/game');
});


