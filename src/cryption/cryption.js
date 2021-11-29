
const fs = require("fs");
var crypto = require("crypto");
const NodeRSA = require("node-rsa");
const padding = crypto.constants.RSA_PKCS1_PADDING;


  /**
	 * Generating md5 hash
	 * 
	 * @param {*} data 
	 * @param {*} callback 
	 */
   function md5Hash(msg, callback) {
    var fsHash = crypto.createHash("md5");
    fsHash.update(msg);
    var md5 = fsHash.digest("hex");
    console.log("MD5 of message is：%s", md5);
    callback(md5);
  },

	/**
	 * Using public key to encrypt
	 * 
	 * @param {*} publicKeyPath 
	 * @param {*} dataStr 
	 * @param {*} callback 
	 */
	function encrypt(publicKeyPath, dataStr, callback) {
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
	* Using private key to decrypt

	* @param {*} privateKeyPath 
	* @param {*} EnDataStr 
	* @param {*} callback 
	*/
  function decrypt(privateKeyPath, EnDataStr, callback) {
    fs.exists(privateKeyPath, function(exists) {
      if (exists) {
        var pem = fs.readFileSync(privateKeyPath, "utf8");
        var key = new NodeRSA(pem);
        var decrypted = key.decrypt(EnDataStr, "utf8");
        console.log("decrypted:" + decrypted);
        callback(decrypted);
      }
    });
  },
