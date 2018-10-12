const express = require('express');
const router = express.Router();
// const { OAuth2Client } = require('google-auth-library');
const multer = require('multer');
const upload = multer();
const CredentialStore = require('./credential-store');

router.post('/session', (req, res) => {
  // TODO: provide reauth status
  if (req.session.profile) {
    const profile = req.session.profile;
    res.json(profile);
  } else {
    res.status(401).send('Unauthorized');
  }
});

router.post('/password', upload.array(), async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  const reauth = req.query.reauth !== undefined;

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

    // If reauth is requested, grant.
    if (reauth) {
      profile.reauth = (new Date()).getTime();
    }

    // Make sure not to include the password in payload.
    delete profile.password;
    delete profile.secondFactors;
    delete profile.reauthKeys;
    req.session.profile = profile;

    res.json(profile);
  } catch (e) {
    console.error(e);
    res.status(401).send('Authentication failed.');
  }
  return;
});

router.post('/change-password', upload.array(), async (req, res) => {
  // TODO: Check strong authentication
  if (!req.session.profile) {
    res.status(401).send('Authentication required.');
    return;
  }
  const old_password = req.body['old-password'];
  const new_password1 = req.body['new-password1'];
  const new_password2 = req.body['new-password2'];

  if (old_password == '' ||
      new_password1 == '' ||
      new_password2 == '') {
    res.status(400).send('Enter all values');
    return;
  // Check new 2 passwords match (and not empty)
  } else if (new_password1 != new_password2) {
    res.status(400).send('New passwords don\'t match');
    return;
  }

  const store = new CredentialStore();
  try {
    const _profile = await store.get(req.session.profile.id);
    if (!_profile)
      throw 'Matching profile not found.';

    // Check old password matches
    if (store.verify(old_password, _profile['password']) === false)
      throw 'Wrong password';

    // Make sure not to include the password in payload.
    _profile.password = store.hash(new_password1);
    await store.save(_profile.id, _profile);

    delete _profile.password;
    delete _profile.secondFactors;
    delete _profile.reauthKeys;
    req.session.profile = _profile;

    res.json(_profile);
  } catch (e) {
    console.error(e);
    res.status(401).send('Authentication failed.');
  }
  return;
});

// router.post('/google', upload.array(), async (req, res) => {
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

router.post('/register', upload.array(), async (req, res) => {
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
    imageurl: ''
  };

  try {
    await store.save(profile['id'], profile);
    delete profile.password;
    delete profile.secondFactors;
    delete profile.reauthKeys;
    req.session.profile = profile;
    res.json(profile);
  } catch (e) {
    res.status(400).send('Storing credential failed.');
  }
  return;
});

router.post('/unregister', upload.array(), async (req, res) => {
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

router.post('/signout', (req, res) => {
  delete req.session.profile;
  res.json({});
});

module.exports = router;
