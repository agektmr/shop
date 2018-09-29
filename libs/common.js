const fs = require('fs');
const path = require('path');

const common = {};

// Extract Google OAuth2 client id from a local file.
const basePath = process.cwd();
common.clientSecrets = JSON.parse(fs.readFileSync(
  path.join(basePath, 'client_secrets.json')
));
if (!common.clientSecrets) {
  console.error('"client_secrets.json" file is missing.');
  process.exit();
}
common.CLIENT_ID = common.clientSecrets.web.client_id;
common.CLIENT_SECRET = common.clientSecrets.web.client_id;

const config = JSON.parse(fs.readFileSync(
  path.join(basePath, 'config.json')
));
if (!config) {
  console.error('"config.json" file is missing.');
  process.exit();
}
common.PROJECT_ID = config.GCLOUD_PROJECT;

module.exports = common;