const express = require('express');
const crypto = require('crypto');
const base64url = require('base64url');
const cbor = require('cbor');
const CredentialStore = require('./credential-store');
// const { Fido2Lib } = require('fido2-lib');

const REAUTH_DURATION = 1000 * 60 * 5; // 5 minutes

function createBase64Random(len = 32) {
  return base64url(crypto.randomBytes(len));
};

function shortSessionCheck(req, res, next) {
  const profile = req.session.profile;
  const now = (new Date()).getTime();
  const acceptable = now - REAUTH_DURATION;
  if (profile.reauth && profile.reauth > acceptable) {
    next();
  } else {
    res.status(401).send('Authentication Required');
  }
}

function sessionCheck(req, res, next) {
  const profile = req.session.profile;
  if (profile) {
    next();
  } else {
    res.status(401).send('Authentication Required');
  }
};

function verifyCredential(credential, challenge, origin) {
  const attestationObject = credential.attestationObject;
  const authenticatorData = credential.authenticatorData;
  if (!attestationObject && !authenticatorData)
    throw 'Invalid request.';

  const clientDataJSON = credential.clientDataJSON;
  // const signature = credential.signature;
  // const userHandle = credential.userHandle;
  const clientData = JSON.parse(base64url.decode(clientDataJSON));

  if (clientData.challenge !== challenge)
    throw 'Wrong challenge code.';

  if (clientData.origin !== origin)
    throw 'Wrong origin.';

  // Temporary workaround for inmature CBOR
  // const buffer = base64url.toBuffer(attestationObject || authenticatorData);
  // const response = cbor.decodeAllSync(buffer)[0];

  const response = {};
  response.fmt = 'none';

  return response;
};

const router = express.Router();

router.post('/keys', sessionCheck, async (req, res) => {
  const profile = req.session.profile;
  const store = new CredentialStore();
  try {
    const _profile = await store.get(profile.id);
    if (_profile) {
      res.json(_profile.secondFactors || []);
    } else {
      throw 'Profile not found';
    }
  } catch (e) {
    console.error(e);
    res.status(400).send('Failed to unregister.');
  }
});

router.post('/makeCred', sessionCheck, async (req, res) => {
  const profile = req.session.profile;
  const reauthFlag = req.query.reauth !== undefined;
  let _profile;
  try {
    const store = new CredentialStore();
    _profile = await store.get(profile.id);
    if (!_profile) throw 'Profile not found';
  } catch (e) {
    res.status(400).send(e);
    return;
  }

  const response = {};
  response.rp = {
    id: req.host,
    name: 'Polykart'
  };
  response.user = {
    displayName: _profile.name || _profile.email || 'No name',
    id: createBase64Random(),
    name: _profile.id
  };
  response.pubKeyCredParams = [{
    type: 'public-key', alg: -7
  }];
  response.timeout = req.body.timeout || 1000 * 30;
  response.challenge = createBase64Random();
  req.session.challenge = response.challenge;

  // Only specify `excludeCredentials` when reauthFlag is `false`
  if (!reauthFlag) {
    for (let authr of _profile.secondFactors) {
      response.excludeCredentials.push({
        id: authr.credId,
        type: 'public-key',
        transports: authr.transports
      });
    }
  }

  const as = {}; // authenticatorSelection
  const aa = req.body.authenticatorSelection.authenticatorAttachment;
  const rr = req.body.authenticatorSelection.requireResidentKey;
  const uv = req.body.authenticatorSelection.userVerification;
  const cp = req.body.attestation; // attestationConveyancePreference
  let asFlag = false;

  if (aa && (aa == 'platform' || aa == 'cross-platform')) {
    asFlag = true;
    as.authenticatorAttachment = aa;
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

router.post('/regCred', sessionCheck, async (req, res) => {
  const profile = req.session.profile;
  const reauthFlag = req.query.reauth !== undefined;
  const credId = req.body.id;
  const type = req.body.type;
  const credential = req.body.response;
  if (!credId || !type || !credential) {
    res.status(400).send('`response` missing in request');
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
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }

  try {
    const challenge = req.session.challenge;
    const origin = `${req.protocol}://${req.get('host')}`;
    const response = verifyCredential(credential, challenge, origin);

    switch (response.fmt) {
      case 'none':
      case 'packed':
        // Ignore attestation
        break;
      case 'fido-u2f':
      case 'android-safetynet':
      default:
        // Not implemented yet
        throw 'Attestation not supported';
    }

    if (reauthFlag) {
      if (!_profile.reauthKeys) {
        _profile.reauthKeys = [];
      }
      const credentialData = {
        credId: credId,
        type: type,
        transports: ['internal'],
        // Ignore attestations for the moment
        // response: response,
        created: (new Date()).getTime(),
        last_used: null
      };
      _profile.reauthKeys.push(credentialData);
    } else {
      if (!_profile.secondFactors) {
        _profile.secondFactors = [];
      }
      const credentialData = {
        credId: credId,
        type: type,
        transports: ['usb', 'ble', 'nfc', 'internal'],
        // Ignore attestations for the moment
        // response: response,
        created: (new Date()).getTime(),
        last_used: null
      };
      _profile.secondFactors.push(credentialData);
    }

    // Ignore authenticator for the moment
    await store.save(profile.id, _profile);
    delete _profile.password;
    delete _profile.secondFactors;
    delete _profile.reauthKeys;
    res.json(_profile);
  } catch (e) {
    res.status(400).send(e);
  }
});

router.post('/getAsst', sessionCheck, async (req, res) => {
  const profile = req.session.profile;
  const reauth = req.query.reauth;
  let _profile;
  try {
    const store = new CredentialStore();
    _profile = await store.get(profile.id);
    if (!_profile) throw 'Profile not found';
  } catch (e) {
    res.status(400).send(e);
  }

  const response = {};
  response.challenge = createBase64Random();
  req.session.challenge = response.challenge;

  if (reauth) {
    for (let authr of _profile.reauthKeys) {
      if (authr.credId == reauth) {
        response.allowCredentials = [{
          id: authr.credId,
          type: 'public-key',
          transports: authr.transports
        }];
        break;
      }
    }
  } else {
    response.allowCredentials = [];
    for (let authr of _profile.secondFactors) {
      response.allowCredentials.push({
        id: authr.credId,
        type: 'public-key',
        transports: authr.transports
      });
    }
  }

  res.json(response);
});

router.post('/authAsst', sessionCheck, async (req, res) => {
  const profile = req.session.profile;
  const reauth = req.query.reauth !== undefined;
  const credId = req.body.id;
  const type = req.body.type;
  const credential = req.body.response;
  if (!credId || !type || !credential) {
    res.status(400).send('`response` missing in request');
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
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }

  try {
    const challenge = req.session.challenge;
    const origin = `${req.protocol}://${req.get('host')}`;
    const response = verifyCredential(credential, challenge, origin);

    switch (response.fmt) {
      case 'none':
      case 'packed':
        // Ignore attestation
        break;
      case 'fido-u2f':
      case 'android-safetynet':
      default:
        // Not implemented yet
        throw 'Attestation not supported';
    }

    let authr = null;
    if (reauth) {
      if (_profile.reauthKeys) {
        for (let _authr of _profile.reauthKeys) {
          if (_authr.credId === credId) {
            authr = _authr;
            break;
          }
        }
      }
    } else {
      if (_profile.secondFactors) {
        for (let _authr of _profile.secondFactors) {
          if (_authr.credId === credId) {
            authr = _authr;
            break;
          }
        }
      }
    }
    if (!authr) {
      res.status(400).send('Matching authenticator not found');
      return;
    }

    // Update timestamp
    const now = (new Date()).getTime();
    authr.last_used = now;
    // TODO: Anything else to update?

console.log(_profile);
    store.save(profile.id, _profile);

    delete _profile.password;
    delete _profile.secondFactors;
    delete _profile.reauthKeys;
    _profile.reauth = now;
    req.session.profile = _profile;
    res.json(_profile);
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }
});

router.post('/remove', sessionCheck, async (req, res) => {
  const profile = req.session.profile;
  const reauth = req.query.reauth;

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

  try {
    if (reauth) {
      if (!_profile.reauthKeys) {
        throw 'Reauth key not registered.';
      }
      for (let i = 0; i < _profile.reauthKeys.length; i++) {
        const cred = _profile.reauthKeys[i];
        if (cred.credId === reauth) {
          _profile.reauthKeys.splice(i, 1);
          await store.save(profile.id, _profile);
          res.json({});
          return;
        }
      }
      throw 'No matching authenticator found.';
    } else {
      if (!_profile.secondFactors) {
        throw 'Authenticator not registered.';
      }
      for (let i = 0; i < _profile.secondFactors.length; i++) {
        const cred = _profile.secondFactors[i];
        if (cred.credId === req.body.credId) {
          _profile.secondFactors.splice(i, 1);
          await store.save(profile.id, _profile);
          res.json({});
          return;
        }
      }
      throw 'No matching authenticator found.';
    }
  } catch (e) {
    console.error(e);
    res.status(400).send(e);
  }
});

module.exports = router;
