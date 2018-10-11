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
const path = require('path');
const session = require('express-session');
const auth = require('./libs/auth');
const webauthn = require('./libs/webauthn');
const common = require('./libs/common');

const AUTH_DURATION = 1000 * 60 * 60 * 24;

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

if (process.env.NODE_ENV === 'production') {
  // app.use(express.static(path.join(__dirname, 'build/es6-bundled'), {
  app.use(express.static(path.join(__dirname, ''), {
    setHeaders: res => {
      res.set('Strict-Tranport-Security', 'max-age=31536000');
    }
  }));
} else {
  app.use(express.static(__dirname));
}
app.use(session({
  secret: common.CLIENT_SECRET,
  maxAge: AUTH_DURATION // 24 hours
}));
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
