//    Copyright 2017 Google
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
const router = express.Router();
const multer = require('multer');
const upload = multer();
const fs = require('fs');
const request = require('request');

// Replace these params based on your own configuration
const APPLE_PAY_CERTIFICATE_PATH = "./certs/apple-pay-cert.pem";
const MERCHANT_IDENTIFIER = "merchant.com.agektmr.payment";
const MERCHANT_DOMAIN = "branded-button.polykart.store";
const MERCHANT_DIAPLAY_NAME = "branded-button.polykart.store";

try {
  fs.accessSync(APPLE_PAY_CERTIFICATE_PATH);
} catch (e) {
  throw new Error('Apple Pay Merchant Identity Certificate is missing.');
}

const cert = fs.readFileSync(APPLE_PAY_CERTIFICATE_PATH);

router.post('/validate/', upload.array(), function (req, res) {
  if (!req.body.validationURL) return res.sendStatus(400);

  const options = {
    url: req.body.validationURL,
    cert: cert,
    key: cert,
    method: 'POST',
    body: {
      merchantIdentifier: MERCHANT_IDENTIFIER,
      domainName: MERCHANT_DOMAIN,
      displayName: MERCHANT_DIAPLAY_NAME
    },
    json: true
  };

  request(options, function(err, response, body) {
    if (err) {
      console.log(err, response, body);
      res.status(500).send(body);
    }
    res.send(body);
  });
});

module.exports = router;