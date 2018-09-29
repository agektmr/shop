const common = require('./common');
const Datastore = require('@google-cloud/datastore');
const bcrypt = require('bcrypt');

module.exports = class CredentialStore {
  constructor() {
    this.STORE_KEY = 'CredentialStore';
    if (process.env.NODE_ENV !== 'production') {
      this.store = new Datastore({
        projectId: common.PROJECT_ID,
        apiEndpoint: 'http://localhost:8081'
      });
    } else {
      this.store = new Datastore({
        projectId: common.PROJECT_ID
      });
    }
  }
  save(id, data) {
    const key = this.store.key([this.STORE_KEY, id]);
    const entity = {
      key: key,
      data: data
    };
    return this.store.upsert(entity);
  }
  get(id) {
    const key = this.store.key([this.STORE_KEY, id]);
    return this.store.get(key).then(res => res[0]);
  }
  remove() {
    const key = this.store.key([this.STORE_KEY, id]);
    return this.store.get(key).then(res => {
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
};
