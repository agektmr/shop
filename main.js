//    Copyright 2018 Google
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

const express = require('express');
const hbs = require('hbs');
const session = require('express-session');
const auth = require('./libs/auth');
const webauthn = require('./libs/webauthn');
const common = require('./libs/common');
const Datastore = require('@google-cloud/datastore');
const DatastoreStore = require('@google-cloud/connect-datastore')(session);

const app = express();
app.enable('trust proxy');
app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.use(express.json());
app.use((req, res, next) => {
  if (!req.secure && process.env.NODE_ENV === 'production') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

const sessionObject = {
  cookie: {
    maxAge: 31536000000, // 1 year
    secure: true
  },
  secret: common.CLIENT_SECRET,
  resave: true,
  saveUninitialized: true
};

if (process.env.NODE_ENV === 'production') {
  sessionObject.store = new DatastoreStore({
    dataset: Datastore({
      prefix: 'express-sessions',
      projectId: common.PROJECT_ID
    })
  });
  app.use(session(sessionObject));
  // app.use(express.static(path.join(__dirname, 'build', 'es6-bundled'), {
  app.use(express.static(__dirname, {
    setHeaders: res => {
      res.set('Strict-Tranport-Security', 'max-age=31536000');
    }
  }));
  // }));
} else {
  sessionObject.store = new DatastoreStore({
    dataset: Datastore({
      prefix: 'express-sessions',
      projectId: common.PROJECT_ID,
      apiEndpoint: 'http://localhost:8081'
    })
  });
  // If localhost, turn off secure cookie
  sessionObject.cookie.secure = false;
  app.use(session(sessionObject));
  // app.use(express.static(path.join(__dirname, 'build', 'es6-bundled')));
  app.use(express.static(__dirname));
}

app.set('views', './templates');

app.use('/auth', auth);
app.use('/webauthn', webauthn);

app.get('*', (req, res) => {
  res.render('index', {
    client_id: common.CLIENT_ID
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`node.js is listening to port: ${PORT}`);
});
