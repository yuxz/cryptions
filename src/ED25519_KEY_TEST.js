
const {
  generateKeyPairSync, 
	createSign,
  createVerify,
	sign,
	verify,
	createPublicKey,
	createPrivateKey,
	X509Certificate

} = require('crypto');
const X509 = require('@root/x509/parsers');

const forge = require('node-forge')
var os = require('os');
if (os.platform() == 'win32') {  
    if (os.arch() == 'ia32') {
        var chilkat = require('@chilkat/ck-node12-win-ia32');
    } else {
        var chilkat = require('@chilkat/ck-node12-win64'); 
    }
} else if (os.platform() == 'linux') {
    if (os.arch() == 'arm') {
        var chilkat = require('@chilkat/ck-node12-arm');
    } else if (os.arch() == 'x86') {
        var chilkat = require('@chilkat/ck-node12-linux32');
    } else {
        var chilkat = require('@chilkat/ck-node12-linux64');
    }
} else if (os.platform() == 'darwin') {
    var chilkat = require('@chilkat/ck-node12-macosx');
}


const ED25519_KEY = require('./ED25519_KEY.js');
/**
 * 
 */
 const { publicKey, privateKey } = generateKeyPairSync('ed25519') 
//  {
//   publicKeyEncoding: {
//     type: 'spki',
//     format: 'der'
//   },
//   privateKeyEncoding: {
//     type: 'pkcs8',
//     format: 'der'
//   }
// });
  


const key = privateKey;
// 根据私钥产生公钥
const pubKey = createPublicKey(key);

// 根据公钥产生公钥
const pubKey2 = createPublicKey({
	key:pubKey.export({type:'spki',format:'pem'}),
	format: 'pem',
	type:'spki'

});

console.log('privateKey.asymmetricKeyDetails: ', key.asymmetricKeyDetails);
console.log('privateKey.asymmetricKeyType: ', key.asymmetricKeyType);
// console.log('privateKey.export: ', key.export({type:'pkcs8',format:'der'}));
// console.log('privateKey.export: ', privateKey.export({type:'pkcs8',format:'jwk'}));
console.log('publicKey.export: ', publicKey.export({type:'spki',format:'der'}));
console.log('pubKey.export: ', pubKey.export({type:'spki',format:'pem'}));
console.log('pubKey2.export: ', pubKey2.export({type:'spki',format:'pem'}));
console.log( 'publicKey2 size: ', pubKey.export({type:'spki',format:'der'}).length)

const priKey = key.export({type:'pkcs8',format:'pem'});
console.log('privateKey.export: ', priKey);
console.log("privateKey.symmetricKeySize: ",key.symmetricKeySize);
console.log("privateKey.type: ", key.type );
console.log("-------------------------------------------------------------------------")


// const keyObject = KeyObject.from(privateKey);


const ed = new ED25519_KEY(key);

// console.log("isPrivate", ed.isPrivate());
console.log("getSKI: ", ed.getSKI());

// console.log("-------------------------------------------------------------------------")


// const msg = "hello world!";
// const sig = sign(null, Buffer.from(msg), privateKey);

// console.log('sig', sig.toString);

// const ver = verify(null, Buffer.from(msg), pubKey, sig);
// console.log('verify', ver);


var pKey = createPrivateKey({
	'key': priKey,
	'format': 'pem',
	'type': 'pkcs8'
});

console.log("createPrivateKey-priKey", pKey.export({type:'pkcs8',format:'pem'}));


console.log('---------------------------sign----------------------------------');

const msg = Buffer.from("I love nodejs!I love nodejs!I love nodejs!I love nodejs!I love nodejs!I love nodejs!I love nodejs!I love nodejs!");
const msg1 = Buffer.from("I love nodejs!I love nodejs!I love nodejs!I love nofdejs!I love nodejs!I love nodejs!I love nodejs!I love nodejs!");

const sig = sign(null , msg, privateKey);

console.log('signature:', sig);
console.log('signature Buffer:', Buffer.from(sig));


console.log('---------------------------verify----------------------------------')

const veri = verify(null, msg, publicKey, sig);

console.log('verify:', veri)

console.log('---------------------------ca--------------------------------------');

// const certPem = "-----BEGIN CERTIFICATE-----\nMIIB7zCCAaGgAwIBAgIUNz0KNTThCckXwOohEC6QcXZVxykwBQYDK2VwMHQxCzAJ\nBgNVBAYTAkpQMQ4wDAYDVQQIEwVUb2t5bzESMBAGA1UEBxMJTWluYXRvLWt1MRMw\nEQYDVQQKEwpKYXNteSBJbmMuMRAwDgYDVQQLEwdSb290IENBMRowGAYDVQQDExFK\nQVNNWSBJTkMgUm9vdCBDQTAeFw0yMTEwMTQwNDM5MDBaFw0yMjExMjExMTQzMDBa\nMCoxDzANBgNVBAsTBmNsaWVudDEXMBUGA1UEAxMOamFzbXktY2EtYWRtaW4wWTAT\nBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT+oND5KeQxsQLMKiHxPK1trVmkt2ZcbmMl\nwtKOL3Oca8XZp4erVucb7j0QCloQVyBsJkDYwawGaqwnpDIzVbPEo2AwXjAOBgNV\nHQ8BAf8EBAMCB4AwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU98ImTLjH/1AJ5Ar4\nXEM5YKoG1vcwHwYDVR0jBBgwFoAU6tWhR2/3u2jz4RB2TFc8yZqFwnEwBQYDK2Vw\nA0EA7wVJyjjAommV6Sccr5DaahR20SPPmHFOA5aHK1rWGDrCajtsm+tHgF2OcKhm\nLlc31piyJz4sl/jRF202/AlABg==\n-----END CERTIFICATE-----\n";
const certPem =`-----BEGIN CERTIFICATE-----
MIIB1zCCAYmgAwIBAgIULL46MUIJwSz4P9i4KCmfxcZbk80wBQYDK2VwMGgxCzAJ
BgNVBAYTAlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEUMBIGA1UEChMLSHlw
ZXJsZWRnZXIxDzANBgNVBAsTBkZhYnJpYzEZMBcGA1UEAxMQZmFicmljLWNhLXNl
cnZlcjAeFw0yMTEwMTEwMTM5MDBaFw0zNjEwMDcwMTM5MDBaMGgxCzAJBgNVBAYT
AlVTMRcwFQYDVQQIEw5Ob3J0aCBDYXJvbGluYTEUMBIGA1UEChMLSHlwZXJsZWRn
ZXIxDzANBgNVBAsTBkZhYnJpYzEZMBcGA1UEAxMQZmFicmljLWNhLXNlcnZlcjAq
MAUGAytlcAMhAGAXQV699Mkbf9Y83N6vwrbNlHcztiplRzISuLTLZ45wo0UwQzAO
BgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUTlsa
+Wkhtn36SB6MFrTOI3IBetYwBQYDK2VwA0EAcgccZJ10vzzjlLu8pvC7rboNJnDZ
Kg6IRT7qqt5fFNJS5XrDxX/IOG9HDQpG6sYBnMHW6zZRxREzvxdRZbgWDQ==
-----END CERTIFICATE-----`

// const x509 =  new X509Certificate(certPem);
// const cert = forge.pki.certificateFromPem(certPem)
// const x509 = X509.parsePkcs1(certPem)
// console.log('x509.publicKey: ', x509.publicKey);
// console.log('x509.publicKey: ', cert);

const pubK = createPublicKey(certPem);//.export({type:'spki', format:'pem'});
console.log(pubK.asymmetricKeyType);



console.log('-------------------------- csr -----------------------------')
// https://javascript.hotexamples.com/zh/examples/node-forge/pki/createCertificationRequest/javascript-pki-createcertificationrequest-method-examples.html
const pki = forge.pki;
const csr = pki.createCertificationRequest()

let keys = forge.pki.ed25519.generateKeyPair({})

csr.publicKey = keys.publicKey
csr.setSubject([
	{shortName: 'CN', value: 'commonName'},
	{shortName: 'C', value: 'US'},
	{shortName: 'ST', value: 'MA'},
	{shortName: 'L', value: 'Boston'},
	{shortName: 'O', value: 'Proxy'},
	{shortName: 'OU', value: '0000'}
])
csr.sign(keys.privateKey)
var output_cert = pki.certificationRequestToPem(csr)
console.log(output_cert);