const fs = require("fs");
var crypto = require("crypto");
const NodeRSA = require("node-rsa");
const padding = crypto.constants.RSA_PKCS1_PADDING;

 /**
	* ECDSAKeyPairGenerator
	* Using ECDSA to generate key pair
	*
	* @param {*} publicPemPath 
	* @param {*} privatePemPath 
	*/
  function ECDSAKeyPairGenerator(publicPemPath, privatePemPath) {
    // const publicKeyPath = "./pem/public.pem";
    // const privateKeyPath = "./pem/private.pem";
    var key = new NodeRSA({ b: 512 });
    key.setOptions({ encryptionScheme: "pkcs1" });

		
    //to save public key
		const publicKey = key.exportKey("public");
    fs.writeFile(publicPemPath, publicKey, err => {
      if (err) throw err;
      console.log("has saved the public key");
    });

   //to save private key
    const privateKey = key.exportKey("private");
    fs.writeFile(privatePemPath, privateKey, err => {
      if (err) throw err;
      console.log("has saved the private key");
    });
  }


	/**
	 * ECDSAEncrypt
	 * 
	 * Using ECDSA and public key to encrypt
	 * 
	 */
	function ECDSAEncrypt(publicKeyPath, dataStr, callback) {
		fs.exists(publicKeyPath, function(exists) {
			if (exists) {
				var pem = fs.readFileSync(publicKeyPath, "utf8");
				var key = new NodeRSA(pem);
				encrypted = key.encrypt(dataStr, "base64");
				console.log("encrypted:" + encrypted);

				callback(encrypted);
			}
		});
	},


	/**
	 * ECDSADecrypt
	 * 
	 * Using ECDSA and private key to decrypt
	 * 
	 */
	function ECDSADecrypt(privateKeyPath, EnDataStr, callback) {
    fs.exists(privateKeyPath, function(exists) {
      if (exists) {
        var pem = fs.readFileSync(privateKeyPath, "utf8");
        var key = new NodeRSA(pem);
        var decrypted = key.decrypt(EnDataStr, "utf8");
        console.log("decrypted:" + decrypted);
        callback(decrypted);
      }
    });
  }

	/**
 * ECDSASignature
 * Using ECDSA and private key to signature
 * 
 */
export default function ECDSASignature(privateKeyPath, dataStr, callback) {
	fs.exists(privateKeyPath, function(exists) {
		if (exists) {
			var pem = fs.readFileSync(privateKeyPath, "utf8");
			var key = new NodeRSA(pem);
			signOut = key.sign(dataStr, "base64");       
			callback(signOut);
		}
	});
}


/**
* ECDSAVerify
* Using ECDSA and public key to signature
* 
* @param {*} publicKeyPath 
* @param {*} dataStr 
* @param {*} signStr 
* @param {*} callback 
*/
export default function ECDSAVerify(publicKeyPath, dataStr, signStr, callback) {
fs.exists(publicKeyPath, function(exists) {
	if (exists) {
		var pem = fs.readFileSync(publicKeyPath, "utf8");
		var key = new NodeRSA(pem);
		var verifySign = key.verify(
			Buffer.from(dataStr),
			signStr,
			"base64",
			"base64"
		);		
		callback(verifySign);
	}
});
}

