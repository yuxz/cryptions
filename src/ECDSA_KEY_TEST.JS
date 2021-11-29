const { generateKeyPairSync } = require('crypto');

const ECDSA_KEY = require('./ECDSA_KEY.js');
// Including publicKey and  privateKey from 
// generateKeyPairSync() method with its 
// parameters
const { publicKey, privateKey } = generateKeyPairSync('ec', {
  namedCurve: 'secp256k1',    // Options
  // publicKeyEncoding: {
  //   type: 'spki',
  //   format: 'der'
  // },
  // privateKeyEncoding: {
  //   type: 'pkcs8',
  //   format: 'der'
  // }
});
  
// Prints asymmetric key pair
console.log("The public key is: ", publicKey);
console.log();
console.log("The private key is: ", privateKey);

const key = privateKey;

const EC = new ECDSA_KEY(key);

console.log("EC.isPrivate: ", EC.isPrivate());
console.log("EC.getSKI: ", EC.getSKI());
console.log("EC.isSymmetric: ", EC.isSymmetric());
console.log("EC.getPublicKey: ", EC.getPublicKey());