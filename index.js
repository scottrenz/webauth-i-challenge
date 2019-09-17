const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs')


const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

const session = require('express-session');

// configure express-session middleware
server.use(
  session({
    name: 'notsession', // default is connect.sid
    secret: 'nobody tosses a dwarf!',
    cookie: {
      maxAge: 1 * 24 * 60 * 60 * 1000,
      secure: false, // true in production, only set cookies over https. Server will not send back a cookie over http.
    }, // 1 day in milliseconds
    httpOnly: true, // don't let JS code access cookies. Browser extensions run JS code on your browser!
    resave: false,
    saveUninitialized: false, // GDPR law against saving cookies automatically
  })
);

function restricted(req, res, next) {
  // we'll read the username and password from headers
  // the client is responsible for setting those headers
  const { username, password } = req.headers;

  // no point on querying the database if the headers are not present
  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: 'Invalid Credentials' });
        }
      })
      .catch(error => {
        res.status(500).json({ message: 'Unexpected error' });
      });
  } else {
    res.status(400).json({ message: 'No credentials provided' });
  }
}

server.get('/', (req, res) => {
  res.send("Welcome to the show");
});

server.post('/api/register', (req, res) => {
  let {username, password} = req.body;
  
  const hash = bcrypt.hashSync(password, 8);

  Users.add({username,password: hash})
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
  });

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      // check password
      bcrypt.compareSync(password, user.password)
      if (user &&  bcrypt.compareSync(password, user.password))
       {
        req.session.user = user; 
        res.status(200).json({ message: `Logged in ${user.username} ${user.id}!` });
      }
       else
        {
        res.status(401).json({ message: 'You shall not pass' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.get('/hash', (req, res) => {
const name = req.query.name
const credentials = req.body;
const hash = bcrypt.hashSync(credentials.password, 14);

res.send(`that hash for ${name} is ${hash}`)
});

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));

/*
write middle where that will check for username and password
and let the request continue to /api/users if credentials are good
return 401 if the credentials are invalid

for get /api/users

*/
