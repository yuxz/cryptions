'use strict';

const nacl = require("tweetnacl");
const util = require("tweetnacl-util");
const paseto = require('paseto');
const { V2 } = paseto
const { V2: { sign, verify } } = paseto
const crypto = require('crypto')
const { promisify } = require('util')
const generateKeyPair = promisify(crypto.generateKeyPair)
const {
  createPrivateKey,
  createPublicKey
} = require('crypto');
const asn = require('asn1.js')

var OneAsymmetricKey = asn.define('OneAsymmetricKey', function() {
  this.seq().obj(
    this.key('version').int(),
    this.key('algorithm').use(AlgorithmIdentifier),
    this.key('privateKey').use(PrivateKey)
  );
});

var PrivateKey = asn.define('PrivateKey', function() {
  this.octstr().contains().obj(
    this.key('privateKey').octstr()
  );
});

var AlgorithmIdentifier = asn.define('AlgorithmIdentifier', function() {
  this.seq().obj(
    this.key('algorithm').objid(),
  );
});


const a = nacl.sign.keyPair();

let sk = a.secretKey;
let sk_cp = Buffer.from(sk.slice(0, 32));

var output = OneAsymmetricKey.encode({
  version: 0,
  privateKey: { privateKey: sk_cp },
  algorithm: { algorithm: '1.3.101.112'.split('.') }
}, 'der');
output.write('04', 12, 1, 'hex');

console.log(output.toString('base64'))

const priv = createPrivateKey({ key: output, format: 'der', type: 'pkcs8' });

const pub = createPublicKey({ key: priv, format: 'der', type: 'pkcs1' });


(async () => {
  const token = await sign({ sub: 'johndoe' }, priv)
  console.log(token)
  const payload = await verify(token, pub)
  console.log(payload)
	console.log(priv.export({type:'pkcs8',format:'der'}).length)
})()