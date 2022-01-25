  var x509 = require('@root/x509')
	var Keypairs = require('@root/keypairs');
	var CSR = require('@root/csr');
	const forge= require('node-forge')
	var ed25519 = forge.pki.ed25519;
	
	// generate a random ED25519 keypair

	
const {
  generateKeyPairSync, 
	createSign,
  createVerify,
	sign,
	verify,
	createPublicKey

} = require('crypto');
/**
 * 
 */

// var CSR = require('../csr.js');
//var PEM = require('@root/pem/packer');
async function run() {
		var pair = await Keypairs.generate();
		console.log('pair.public', pair.public)

		// let keyPair = generateKeyPairSync('ed25519') 
		// keyPair = generateKeyPairSync('ec', {
		// 	namedCurve: 'sect239k1'
		// });
		// // var keyPair = ed25519.generateKeyPair();
	  // console.log('ed25519.pub', keyPair.publicKey)


		var hex = CSR.request({
			jwk: pair.public,
			// jwk: keyPair.publicKey,
			domains: ['example.com', '*.example.com', 'foo.bar.example.com'],
			encoding: 'hex'
		});

		//console.log(hex);
		CSR.csr({
			jwk: pair.private,
			// jwk: keyPair.privateKey,
			domains: ['example.com', '*.example.com', 'foo.bar.example.com'],
			encoding: 'pem'
		}).then(function(csr) {
			//var csr = PEM.packBlock({ type: 'CERTIFICATE REQUEST', bytes: der });
			console.log(csr);
			if (!/^-----BEGIN CERTIFICATE REQUEST-----\s*MII/m.test(csr)) {
				throw new Error("invalid CSR PEM");
			}
			console.info('PASS: (if it looks right)');
		});
	}

run();