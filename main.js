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
const multer = require('multer');
const upload = multer();
const { OAuth2Client } = require('google-auth-library');
const session = require('express-session');
const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const request = require('request');

// Extract Google OAuth2 client id from a local file.
const clientSecrets = JSON.parse(fs.readFileSync('./client_secrets.json'));
if (!clientSecrets) {
  console.error('"client_secrets.json" file is missing.');
  process.exit();
}
const CLIENT_ID = clientSecrets.web.client_id;

const config = JSON.parse(fs.readFileSync('./config.json'));
if (!config) {
  console.error('"config.json" file is missing.');
  process.exit();
}
const PROJECT_ID = config.GCLOUD_PROJECT;

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
  app.use(express.static(path.join(__dirname, 'build/es6-bundled'), {
    setHeaders: res => {
      res.set('Strict-Tranport-Security', 'max-age=31536000');
    }
  }));
} else {
  app.use(express.static(__dirname));
}
app.use(session({
  secret: clientSecrets.web.client_secret,
  maxAge: 24 * 60 * 60 * 1000 // 24 hours
}));
app.set('views', './templates');

class CredentialStore {
  constructor() {
    this.STORE_KEY = 'CredentialStore';
    if (process.env.NODE_ENV !== 'production') {
      this.store = new Datastore({
        projectId: PROJECT_ID,
        apiEndpoint: 'http://localhost:8081'
      });
    } else {
      this.store = new Datastore({
        projectId: PROJECT_ID
      });
    }
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

app.post('/auth/session', (req, res) => {
  if (req.session.profile) {
    const profile = req.session.profile;
    res.json(profile);
  } else {
    res.status(401).send('Unauthorized');
  }
});

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
    delete profile['authenticators'];
    req.session.profile = profile;

    res.json(profile);
  } catch (e) {
    console.error(e);
    res.status(401).send('Authentication failed.');
  }
  return;
});

// app.post('/auth/google', upload.array(), async (req, res) => {
//   const id_token = req.body.id_token;

//   const client = new OAuth2Client(CLIENT_ID);
//   const store = new CredentialStore();
//   try {
//     const ticket = await client.verifyIdToken({
//       idToken: id_token,
//       audience: CLIENT_ID
//     });
//     const idinfo = ticket.getPayload();

//     if (!idinfo)
//       throw 'ID Token not verified.';

//     if (idinfo.iss !== 'accounts.google.com' &&
//         idinfo.iss !== 'https://accounts.google.com' )
//       throw 'Wrong issuer.';

//     await store.save(idinfo.sub, idinfo);
//     const profile = {
//       id:       idinfo.sub,
//       imageUrl: idinfo.picture,
//       name:     idinfo.name,
//       email:    idinfo.email
//     }
//     req.session.profile = profile;
//     res.json(profile);
//   } catch (e) {
//     console.error(e);
//     res.status(401).send('Authentication failed.');
//   }
// });

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
    delete profile['authenticators'];
    req.session.profile = profile;
    res.json(profile);
  } catch (e) {
    res.status(400).send('Storing credential failed.');
  }
  return;
});

app.post('/unregister', upload.array(), async (req, res) => {
  const id = req.body.id;
  if (!id) {
    res.status(400).status('User id not specified.');
    return;
  }

  const store = new CredentialStore();
  try {
    await store.remove(id);
    req.session.profile = null;
    res.send('Success');
  } catch (e) {
    console.error(e);
    res.status(400).send('Failed to unregister.');
  }
});

app.post('/signout', (req, res) => {
  req.session.profile = null;
  res.json({});
});

app.post('/webauthn/keys', async (req, res) => {
  const profile = req.session.profile;
  if (!profile) {
    res.status(400).send('Unauthorized');
    return;
  }

  const store = new CredentialStore();
  try {
    const _profile = await store.get(profile.id);
    if (_profile) {
      res.json(_profile.authenticators || []);
    } else {
      throw 'Profile not found';
    }
  } catch (e) {
    console.error(e);
    res.status(400).send('Failed to unregister.');
  }
});

app.post('/webauthn/makeCred', async (req, res) => {
  const response = {};
  const profile = req.session.profile;
  /**
   * Expected option items:
   * {
   *   timeout?,
   *   attestationAttachment? = 'platform' | 'cross-platform',
   *   requireResidentKey? = true | false,
   *   userVerification? = 'required' | 'preferred' | 'discouraged',
   *  attestation? = 'none' | 'indirect' | 'direct'
   * }
   **/
  if (profile) {
    let _profile;
    try {
      const store = new CredentialStore();
      _profile = await store.get(profile.id);
      if (!_profile) throw 'Profile not found';
    } catch (e) {
      res.status(400).send(e);
    }
    /**
     * Response format:
     * {
     *   rp,
     *   user,
     *   challenge,
     *   pubKeyCredParams,
     *   timeout?,
     *   excludeCredentials?,
     *   authenticatorSelection? = {
     *     attestationAttachment? = 'platform' | 'cross-platform',
     *     requireResidentKey? = true | false,
     *     userVerification? = 'required' | 'preferred' | 'discouraged'
     *   },
     *   attestation?,
     *   extensions?
     * }
     **/
    response.rp = {
      id: req.host,
      name: 'Polykart'
    };
    response.user = {
      displayName: profile.name || profile.email || 'No name',
      id: createBase64Random(),
      name: profile.id
    };
    response.pubKeyCredParams = [{
      type: 'public-key', alg: -7
    }];
    response.timeout = req.body.timeout || 1000 * 30;
    response.challenge = createBase64Random();
    req.session.challenge = response.challenge;
    if (_profile.authenticators) {
      response.excludeCredentials = [];
      for (let authr of _profile.authenticators) {
        response.excludeCredentials.push({
          type: authr.type,
          id: authr.credId,
          // TODO: How do I get this?
          // transports: authr.transports
        })
      }
    }

    const as = {}; // authenticatorSelection
    const aa = req.body.attestationAttachment;
    const rr = req.body.requireResidentKey;
    const uv = req.body.userVerification;
    const cp = req.body.attestation; // attestationConveyancePreference
    let asFlag = false;

    if (aa && (aa == 'platform' || aa == 'cross-platform')) {
      asFlag = true;
      as.attestationAttachment = aa;
    }
    if (rr && typeof rr == boolean) {
      asFlag = true;
      as.requireResidentKey = rr;
    }
    if (uv && (uv == 'required' || uv == 'preferred' || uv == 'discouraged')) {
      asFlag = true;
      as.userVerification = uv;
    }
    if (asFlag) {
      response.authenticatorSelection = as;
    }
    if (cp && (cp == 'none' || cp == 'indirect' || cp == 'direct')) {
      response.attestation = cp;
    }

    res.json(response);
  } else {
    res.status(401).send('Not authorized');
  }
});

app.post('/webauthn/regCred', async (req, res) => {
  const profile = req.session.profile;
  if (!profile) {
    console.error('Not signed in');
    res.status(400).send('Not signed in');
  }
  const credId = req.body.id;
  const type = req.body.type;
  if (!req.body.response) {
    res.status(400).send('`response` missing in request');
    return;
  }
  const attestationObject = req.body.response.attestationObject;
  const clientDataJSON = req.body.response.clientDataJSON;
  // const signature = req.body.response.signature;
  // const userHandle = req.body.response.userHandle;
  const clientData = JSON.parse(base64url.decode(clientDataJSON));

  if (clientData.challenge !== req.session.challenge) {
    res.status(400).send('Wrong challenge code.');
    return;
  }
  if (clientData.origin !== `${req.protocol}://${req.get('host')}`) {
    res.status(400).send('Wrong origin.');
    return;
  }

  const attsBuffer = base64url.toBuffer(attestationObject);
  const response = cbor.decodeAllSync(attsBuffer)[0];
console.log(response);

  switch (response.fmt) {
    case 'none':
      // Ignore attestation
      break;
    case 'fido-u2f':
    case 'android-safetynet':
    case 'packed':
    default:
      // Not implemented yet
      throw 'Attestation not supported';
  }

  // Ignore authenticator for the moment
  const store = new CredentialStore();
  try {
    const _profile = await store.get(profile.id);
    if (_profile) {
      // Append new credential
      if (!_profile.authenticators) {
        _profile.authenticators = [];
      }
      const publicKeyCredential = {
        credId: credId,
        type: type,
        // Ignore attestations for the moment
        response: response,
        created: (new Date()).getTime(),
        last_used: null
      }
      _profile.authenticators.push(publicKeyCredential);

      store.save(profile.id, _profile);
      delete _profile['password'];
      delete _profile['authenticators'];
      res.json(_profile);
    } else {
      throw 'User profile not found.';
    }
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }
});

app.post('/webauthn/getAsst', async (req, res) => {
  const response = {};
  const profile = req.session.profile;
  if (profile) {
    let _profile;
    try {
      const store = new CredentialStore();
      _profile = await store.get(profile.id);
      if (!_profile) throw 'Profile not found';
    } catch (e) {
      res.status(400).send(e);
    }
    /**
     * Response format:
     * {
     *   challenge,
     *   allowCredentials? = [{
     *     id,
     *     type,
     *     transport?
     *   }, ...]
     * }
     **/
    response.challenge = createBase64Random();
    req.session.challenge = response.challenge;
    if (_profile.authenticators) {
      response.allowCredentials = [];
      for (let authr of _profile.authenticators) {
        response.allowCredentials.push({
          type: authr.type,
          id: authr.credId,
          // TODO: is this really ok?
          transports: ['usb', 'nfc', 'ble', 'internal']
        });
      }
    }

    res.json(response);
  } else {
    res.status(401).send('Not authorized');
  }
});

app.post('/webauthn/authAsst', async (req, res) => {
  const profile = req.session.profile;
  if (!profile) {
    console.error('Not signed in');
    res.status(400).send('Not signed in');
  }

  // Ignore authenticator for the moment
  const store = new CredentialStore();
  let _profile;
  try {
    _profile = await store.get(profile.id);
    if (!_profile) {
      throw 'User profile not found.';
    }
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }

  const credId = req.body.id;
  const type = req.body.type;
  if (!req.body.response) {
    res.status(400).send('`response` missing in request');
    return;
  }
  const authenticatorData = req.body.response.authenticatorData;
  const clientDataJSON = req.body.response.clientDataJSON;
  // const signature = req.body.response.signature;
  // const userHandle = req.body.response.userHandle;
  const clientData = JSON.parse(base64url.decode(clientDataJSON));

  if (clientData.challenge !== req.session.challenge) {
    res.status(400).send('Wrong challenge code.');
    return;
  }
  if (clientData.origin !== `${req.protocol}://${req.get('host')}`) {
    res.status(400).send('Wrong origin.');
    return;
  }

  let authr = null;
  if (_profile.authenticators) {
    for (let _authr of _profile.authenticators) {
      if (_authr.credId === credId) {
        authr = _authr;
        break;
      }
    }
  }
  if (!authr) {
    res.status(400).send('Matching authenticator not found');
    return;
  }

//   const authrBuffer = base64url.toBuffer(authenticatorData);
//   const response = cbor.decodeAllSync(authrBuffer)[0];
// console.log(response);

//   switch (response.fmt) {
//     case 'none':
//       // Ignore attestation
//       break;
//     case 'fido-u2f':
//     case 'android-safetynet':
//     case 'packed':
//     default:
//       // Not implemented yet
//       throw 'Attestation not supported';
//   }

  // Update timestamp
  authr.last_used = (new Date()).getTime();
  // TODO: Anything else to update?

console.log(_profile);
  store.save(profile.id, _profile);

  delete _profile['password'];
  delete _profile['authenticators'];
  res.json(_profile);
});

app.post('/webauthn/remove', async (req, res) => {
  const profile = req.session.profile;
  if (!profile) {
    res.status(400).send('Invalid request');
    return;
  }
  // Ignore authenticator for the moment
  const store = new CredentialStore();
  let _profile;
  try {
    _profile = await store.get(profile.id);
    if (!_profile) {
      throw 'User profile not found.';
    }
    if (!_profile.authenticators) {
      throw 'Authenticator not registered.';
    }
    for (let i = 0; i < _profile.authenticators.length; i++) {
      const cred = _profile.authenticators[i];
      if (cred.credId === req.body.credId) {
        _profile.authenticators.splice(i, 1);
        store.save(profile.id, _profile);
        res.status(200).send({});
        return;
      }
    }
    res.status(400).send('No matching authenticator found.');
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }
});

const createBase64Random = (len = 32) => {
  return base64url(crypto.randomBytes(len));
}

app.get('*', (req, res) => {
  res.render('index', {
    client_id: CLIENT_ID
  });
});

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`node.js is listening to port: ${PORT}`);
});
