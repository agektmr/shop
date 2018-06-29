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
const bcrypt = require('bcrypt');
const fs = require('fs');
const Datastore = require('@google-cloud/datastore');
const bodyParser = require('body-parser');
const request = require('request');

const app = express();
app.use(bodyParser.json());
app.enable('trust proxy');
app.set('view engine', 'html');
app.engine('html', hbs.__express);
app.use((req, res, next) => {
  if (!req.secure && req.headers.host.indexOf('localhost') < 0) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});
app.use(express.static(path.join(__dirname, 'build/es6-bundled'), {
  setHeaders: res => {
    res.set('Strict-Tranport-Security', 'max-age=31536000');
  }
}));
app.set('views', './templates');


// from google.appengine.ext import vendor
// vendor.add('lib')

// import os
// import sys
// import json
// import urllib
// from bcrypt import bcrypt
// from flask import Flask, request, make_response, render_template, session
// from oauth2client import client

// from google.appengine.ext import ndb
// from google.appengine.api import urlfetch

// FACEBOOK_APPID=os.getenv('FACEBOOK_APPID')
// FACEBOOK_APPTOKEN=os.getenv('FACEBOOK_APPTOKEN', None)

// app = Flask(
//     __name__,
//     template_folder='templates'
// )
// app.debug = True

// # Does `client_secrets.json` file exist?
// if os.path.isfile('client_secrets.json') is False:
//     sys.exit('client_secrets.json not found.')

// # Load `client_secrets.json` file
// keys = json.loads(open('client_secrets.json', 'r').read())['web']

// CLIENT_ID = keys['client_id']

// # `SECRET_KEY` can be anything as long as it is hidden, but we use
// # `client_secret` here for convenience
// SECRET_KEY = keys['client_secret']
// app.config.update(
//     SECRET_KEY=SECRET_KEY
// )

class CredentialStore {
  constructor() {
    this.store = new Datastore({
      projectId: 'polykart-credential-payment'
    });
  }
  async get_by_id(id) {
    return new Promise((resolve, reject) => {
      const key = this.store.key(['id', id]);
      this.store.get(key, (err, entity) => {
        if (err) {
          reject(err);
        } else {
          resolve(entity);
        }
      });
    });
  }
  remove() {

  }
  hash() {

  }
  verify() {

  }
}

// # App Engine Datastore to save credentials
// class CredentialStore(ndb.Model):
//     profile = ndb.JsonProperty()

//     @classmethod
//     def remove(cls, key):
//         ndb.Key(cls.__name__, key).delete()

//     @classmethod
//     def hash(cls, password):
//         return bcrypt.hashpw(password, bcrypt.gensalt())

//     @classmethod
//     def verify(cls, password, hashed):
//         if bcrypt.hashpw(password, hashed) == hashed:
//             return True
//         else:
//             return False


// @app.before_request
// def csrf_protect():
//     # All incoming POST requests will pass through this
//     if request.method == 'POST':
//         # Obtain the custom request header to check if this request
//         # is from a browser and is intentional.
//         header = request.headers.get('X-Requested-With', None)
//         if not header:
//             # Return 403 if empty or they are different
//             return make_response('', 403)


app.post('/auth/password', (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    res.status(400).send('Bad Request');
    return;
  }

  const store = CredentialStore.get_by_id(email);
  if (!store) {
    res.status(401).send('Authentication failed.');
    return;
  }

  const profile = store.profile;

  if (!profile) {
    res.status(401).send('Authentication failed.');
    return;
  }

  if (CredentialStore.verify(password, profile['password']) === false) {
    res.status(401).send('Authentication failed.');
    return;
  }

  profile.pop('password');

  res.status(200).send(JSON.stringify(profile));
});

app.post('/auth/google', (req, res) => {
  const id_token = req.body.id_token;
});

// @app.route('/auth/google', methods=['POST'])
// def gauth():
//     # The POST should include `id_token`
//     id_token = request.form.get('id_token', '')[:3072]

//     # Verify the `id_token` using API Client Library
//     idinfo = client.verify_id_token(id_token, CLIENT_ID)

//     # Additional verification: See if `iss` matches Google issuer string
//     if idinfo['iss'] not in ['accounts.google.com',
//                              'https://accounts.google.com']:
//         return make_response('Wrong Issuer.', 401)

//     # For now, we'll always store profile data after successfully
//     # verifying the token and consider the user authenticated.
//     store = CredentialStore(id=idinfo['sub'], profile=idinfo)
//     store.put()

//     # Construct a profile object
//     profile = {
//         'id':        idinfo.get('sub', None),
//         'imageUrl':  idinfo.get('picture', None),
//         'name':      idinfo.get('name', None),
//         'email':     idinfo.get('email', None)
//     }

//     # Not making a session for demo purpose/simplicity
//     return make_response(json.dumps(profile), 200)


// @app.route('/auth/facebook', methods=['POST'])
// def fblogin():
//     # The POST should include `access_token` from Facebook
//     access_token = request.form.get('access_token', None)[:3072]

//     # If the access_token is `None`, fail.
//     if access_token is None:
//         return make_response('Authentication failed.', 401)

//     app_token = FACEBOOK_APPTOKEN if FACEBOOK_APPTOKEN is not None else access_token

//     # Verify the access token using Facebook API
//     params = {
//         'input_token':  access_token,
//         'access_token': app_token
//     }
//     r = urlfetch.fetch('https://graph.facebook.com/debug_token?' +
//                        urllib.urlencode(params))
//     result = json.loads(r.content)

//     # If the response includes `is_valid` being false, fail
//     if result['data']['is_valid'] is False:
//         return make_response('Authentication failed.', 401)

//     # Make an API request to Facebook using OAuth
//     r = urlfetch.fetch('https://graph.facebook.com/me?fields=name,email',
//                        headers={'Authorization': 'OAuth '+access_token})
//     idinfo = json.loads(r.content)

//     # Save the Facebook profile
//     store = CredentialStore(id=idinfo['id'], profile=idinfo)
//     store.put()

//     # Obtain the Facebook user's image
//     profile = idinfo
//     profile['imageUrl'] = 'https://graph.facebook.com/' + profile['id'] +\
//         '/picture?width=96&height=96'

//     # Not making a session for demo purpose/simplicity
//     return make_response(json.dumps(profile), 200)


app.post('/register', (req, res) => {
  const email = req.body.email;
  const _password = req.body.password;

  if (!email || !password) {
    res.status(400).send('Bad Request');
    return;
  }

  const password = CredentialStore.hash(_password);

  const profile = {
    id: email,
    email: email,
    name: req.body.name,
    password: password,
    imageUrl: ''
  };

  const store = CredentialStore(profile['id'], profile);
  store.put();

  profile.pop('password');

  res.status(200).send(JSON.stringify(profile));
});

// @app.route('/unregister', methods=['POST'])
// def unregister():
//     if 'id' not in request.form:
//         make_response('User id not specified', 400)

//     id = request.form.get('id', '')
//     store = CredentialStore.get_by_id(str(id))

//     if store is None:
//         make_response('User not registered', 400)

//     profile = store.profile

//     if profile is None:
//         return make_response('Failed', 400)

//     # Remove the user account
//     CredentialStore.remove(str(id))
//     # Not terminating a session for demo purpose/simplicity
//     return make_response('Success', 200)


// @app.route('/signout', methods=['POST'])
// def signout():
//     # Not terminating a session for demo purpose/simplicity
//     return make_response(json.dumps({}), 200)

app.get('/', (req, res) => {
  const clientSecrets = JSON.parse(fs.readFileSync('./client_secrets.json'));
  res.render('index', { client_id: clientSecrets.web.client_id });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`node.js is listening to port: ${PORT}`);
});
