const fs = require("fs");
var crypto = require("crypto");
const NodeRSA = require("node-rsa");
const padding = crypto.constants.RSA_PKCS1_PADDING;

 /**
	* RSAKeyPairGenerator
	* Using RSA to generate key pair
	*
	* @param {*} publicPemPath 
	* @param {*} privatePemPath 
	*/
  function RSAKeyPairGenerator(publicPemPath, privatePemPath) {
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
	 * RSAEncrypt
	 * 
	 * Using RSA and public key to encrypt
	 * 
	 */
	function RSAEncrypt(publicKeyPath, dataStr, callback) {
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
	 * RSADecrypt
	 * 
	 * Using RSA and private key to decrypt
	 * 
	 */
	function RSADecrypt(privateKeyPath, EnDataStr, callback) {
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
 * RSASignature
 * Using RSA and private key to signature
 * 
 */
export default function RSASignature(privateKeyPath, dataStr, callback) {
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
* RSAVerify
* Using RSA and public key to signature
* 
* @param {*} publicKeyPath 
* @param {*} dataStr 
* @param {*} signStr 
* @param {*} callback 
*/
export default function RSAVerify(publicKeyPath, dataStr, signStr, callback) {
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

//   SelfSign: function SelfSign(attrs, savePath) {
//     var selfsigned = require("selfsigned");
//     // var attrs = [
//     //   { name: "commonName", value: "contoso.com", card: "130521199203080776" }
//     // ];
//     var pems = selfsigned.generate(attrs, { days: 365 });
//     console.log(pems);
//     var privateCert = pems.private;
//     var publicCert = pems.public;
//     var cert = pems.cert;
//     this.SaveData(privateCert, "private.pem", savePath);
//     this.SaveData(publicCert, "public.pem", savePath);
//     this.SaveData(cert, "cert.pem", savePath);
//     console.log("----private-------" + pems.private);
//   },
//   SaveData: function SaveData(data, fileName, filePath) {
//     fs.writeFile(
//       filePath + "/" + fileName,
//       data,
//       { flag: "w", encoding: "utf-8", mode: "0666" },
//       function(err) {
//         if (err) {
//           console.log("文件写入失败");
//         } else {
//           console.log("文件写入成功");
//         }
//       }
//     );
//   }
// };
