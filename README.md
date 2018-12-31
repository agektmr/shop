# SHOP

### Setup

##### Prerequisites

Install [polymer-cli](https://github.com/Polymer/polymer-cli):
(Need at least npm v0.3.0)

    npm install -g polymer-cli

Install [Google Cloud SDK](https://cloud.google.com/sdk/) to use App Engine.

Create a project in [Google API Console](https://console.developers.google.com/)
following [these
steps](https://developers.google.com/identity/sign-in/web/devconsole-project).
Once it's done:
* Download `client_secret_****.json`, rename it to `client_secrets.json`
* Place `client_secrets.json` at root of this project

You also need to set up Apple Pay and place .pem file at `/certs` directory.

##### Setup
    # Clone from GitHub
    git clone https://github.com/Polymer/shop.git
    cd shop
    npm install

    # Build
    npm run build

### Start the development server
    gcloud beta emulators datastore start
    npm start
