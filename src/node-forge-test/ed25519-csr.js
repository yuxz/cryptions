var forge = require('../vendor/node-forge');

console.log('Generating 1024-bit key-pair...');
var keys = forge.pki.ed25519.generateKeyPair();
console.log('Key-pair created.');

console.log('Creating certification request (CSR) ...');
// 1. 创建csr对象
var csr = forge.pki.createCertificationRequest();

// 2. 设置csr对象publicKey属性
csr.publicKey = keys.publicKey;
console.log("keys.publicKey: ", keys.publicKey);
console.log("keys.publicKey-hex: ", keys.publicKey.toString('hex'));
console.log("keys.publicKey-base64: ", keys.publicKey.toString('base64'));
console.log("")

// 3. 设置csr对象subject属性
csr.setSubject([{
  name: 'commonName',
  value: 'example.org'
}, {
  name: 'countryName',
  value: 'US'
}, {
  shortName: 'ST',
  value: 'Virginia'
}, {
  name: 'localityName',
  value: 'Blacksburg'
}, {
  name: 'organizationName',
  value: 'Test'
}, {
  shortName: 'OU',
  value: 'Test'
}]);

// 4. 设置csr对象attributes属性
// add optional attributes
csr.setAttributes([{
  name: 'challengePassword',
  value: 'password'
}, {
  name: 'unstructuredName',
  value: 'My company'
}]);

// // 5.对csr publicKey、subject、attributes信息进行签名
// // sign certification request
// csr.signED(keys.privateKey, forge.md.sha256.create());
csr.signED(keys.privateKey);
// csr.signED(keys.privateKey, forge.md.md5.create());
// csr.signED(keys.privateKey);
// console.log('Certification request (CSR) created.');

// // PEM-format keys and csr
var pem = {
//   privateKey: forge.pki.privateKeyToPem(keys.privateKey),
//   publicKey: forge.pki.publicKeyToPem(keys.publicKey),


// 	// 6. 将签名publicKey、subject、attributes and signature 形成csr Pem格式文件  
  csr: forge.pki.certificationRequestToPem(csr)
};

// console.log('\nKey-Pair:');
// console.log(pem.privateKey);
// console.log(pem.publicKey);

// console.log('\nCertification Request (CSR):');
console.log(pem.csr);

// verify certification request
try {
  if(csr.verify()) {
    console.log('Certification request (CSR) verified.');
  } else {
    throw new Error('Signature not verified.');
  }
} catch(err) {
  console.log('Certification request (CSR) verification failure: ' +
    JSON.stringify(err, null, 2));
}