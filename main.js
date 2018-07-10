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
const bcrypt = require('bcrypt');
const fs = require('fs');
const Datastore = require('@google-cloud/datastore');
const multer = require('multer');
const upload = multer();
const { OAuth2Client } = require('google-auth-library');
const request = require('request');

// Extract Google OAuth2 client id from a local file.
const clientSecrets = JSON.parse(fs.readFileSync('./client_secrets.json'));
if (!clientSecrets) {
  console.error('"client_secrets.json" file is missing.');
  process.exit();
}
const CLIENT_ID = clientSecrets.web.client_id;

const app = express();
app.enable('trust proxy');
app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.use((req, res, next) => {
  if (!req.secure && req.headers.host.indexOf('localhost') < 0) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});
app.use(express.static(__dirname, {
// app.use(express.static(path.join(__dirname, 'build/es6-bundled'), {
  setHeaders: res => {
    res.set('Strict-Tranport-Security', 'max-age=31536000');
  }
}));
app.set('views', './templates');

class CredentialStore {
  constructor() {
    this.STORE_KEY = 'CredentialStore';
    this.store = new Datastore({
      projectId: 'polykart-credential-payment',
      apiEndpoint: 'http://localhost:8081'
    });
  }
  save(id, data) {
    const key = this.store.key([this.STORE_KEY, id]);
    const entity = {
      key: key,
      data: data
    }
    return this.store.upsert(entity);
  }
  get(id) {
    const key = this.store.key([this.STORE_KEY, id]);
    return this.store.get(key).then(res => res[0]);
  }
  remove() {
    const key = this.store.key([this.STORE_KEY, id]);
    return this.store.get(key)
    .then(res => {
      if (res.length > 0) {
        return this.store.delete(key);
      } else {
        throw 'User id not registered.';
      }
    });
  }
  hash(passwd) {
    const salt = bcrypt.genSaltSync(10);
    return bcrypt.hashSync(passwd, salt);
  }
  verify(passwd, hashed) {
    return bcrypt.compareSync(passwd, hashed);
  }
}

app.post('/auth/password', upload.array(), async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    res.status(400).send('Bad Request');
    return;
  }

  const store = new CredentialStore();
  try {
    const profile = await store.get(email);
    if (!profile)
      throw 'Matching profile not found.';

    if (store.verify(password, profile['password']) === false)
      throw 'Wrong password';

    // Make sure not to include the password in payload.
    delete profile['password'];

    res.status(200).send(JSON.stringify(profile));
  } catch (e) {
    console.error(e);
    res.status(401).send('Authentication failed.');
  }
  return;
});

app.post('/auth/google', upload.array(), async (req, res) => {
  const id_token = req.body.id_token;

  const client = new OAuth2Client(CLIENT_ID);
  const store = new CredentialStore();
  try {
    const ticket = await client.verifyIdToken({
      idToken: id_token,
      audience: CLIENT_ID
    });
    const idinfo = ticket.getPayload();

    if (!idinfo)
      throw 'ID Token not verified.';

    if (idinfo.iss !== 'accounts.google.com' &&
        idinfo.iss !== 'https://accounts.google.com' )
      throw 'Wrong issuer.';

    await store.save(idinfo.sub, idinfo);
    const profile = {
      id:       idinfo.sub,
      imageUrl: idinfo.picture,
      name:     idinfo.name,
      email:    idinfo.email
    }
    res.status(200).send(JSON.stringify(profile));
  } catch (e) {
    console.error(e);
    res.status(401).send('Authentication failed.');
  }
});

app.post('/register', upload.array(), async (req, res) => {
  const email = req.body.email;
  const _password = req.body.password;

  if (!email || !_password) {
    res.status(400).send('Bad Request');
    return;
  }

  const store = new CredentialStore();
  const password = store.hash(_password);

  const profile = {
    id: email,
    email: email,
    name: req.body.name,
    password: password,
    imageUrl: ''
  };

  try {
    await store.save(profile['id'], profile);
    delete profile['password'];
    res.status(200).send(JSON.stringify(profile));
  } catch (e) {
    res.status(400).send('Storing credential failed.');
  }
  return;
});

app.post('/unregister', upload.array(), async (req, res) => {
  const id = req.body.id;
  if (!id)
    res.status(400).status('User id not specified.');

  const store = new CredentialStore();
  try {
    await store.remove(id);
    res.status(200).send('Success');
  } catch (e) {
    console.error(e);
    res.status(400).send('Failed to unregister.');
  }
});

app.post('/signout', (req, res) => {
  res.status(200).send('{}');
});

app.get('/', (req, res) => {
  res.render('index', {
    client_id: CLIENT_ID
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`node.js is listening to port: ${PORT}`);
});