const express = require('express');
const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const CredentialStore = require('./credential-store');
// const { Fido2Lib } = require('fido2-lib');

const createBase64Random = (len = 32) => {
  return base64url(crypto.randomBytes(len));
};

const router = express.Router();

router.post('/keys', async (req, res) => {
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

router.post('/makeCred', async (req, res) => {
  const profile = req.session.profile;
  if (!profile) {
    res.status(401).send('Not authorized');
    return;
  }
  let _profile;
  try {
    const store = new CredentialStore();
    _profile = await store.get(profile.id);
    if (!_profile) throw 'Profile not found';
  } catch (e) {
    res.status(400).send(e);
    return;
  }

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
  // const fido = new Fido2Lib({
  //   timeout: req.body.timeout,
  //   rpId: req.host,
  //   rpName:'Polykart',
  //   challengeSize: 32,
  //   authenticator
  // });
  // const options = await fido.attestationOptions();
  // console.log(options);
  // return;
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
  const response = {};
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
      });
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
});

router.post('/regCred', async (req, res) => {
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
      console.error('Attestation not supported');
      break;
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
      };
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

router.post('/getAsst', async (req, res) => {
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

router.post('/authAsst', async (req, res) => {
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
  // const type = req.body.type;
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

router.post('/remove', async (req, res) => {
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

module.exports = router;
