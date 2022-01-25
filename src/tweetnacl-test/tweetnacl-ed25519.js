const nacl = require('tweetnacl');
const util = require('tweetnacl-util');
const ed2curve = require('ed2curve');
// const isUndefined = require("lodash/isUndefined");
// const isNull = require("lodash/isNull");
// const isString = require("lodash/isString");

/**
 * Curve25519/Ed25519/X25519  椭圆曲线加密 / 签名 /密钥交换算法
 * 
 * 秘钥交换： 我的私钥 + 对方公钥 = 秘钥 
 * 加密：明文 + 秘钥 = 密文 + 秘钥 = 明文
 * 签名：明文 + 私钥 = 签名 + 公钥 = 验证 + 明文 
 * 
 */


	/**
	 * genKeyPair
	 * 
	 * Basing ed25519 to generate key pair
	 */
  function genKeyPair(){
		// Generates new random key pair for signing
		const keyPair = nacl.sign.keyPair();
				
		// need to store secretKeyString in browser
		//const secretKey = keyPair.secretKey;
		//const secretKeyString = util.encodeBase64(keyPair.secretKey);

		// need to share publicKeyString with peers
		//const publicKey = keyPair.publicKey;
		//const publicKeyString = util.encodeBase64(keyPair.publicKey);		

		// console.log("secretKey", this.secretKey);
		// console.log("secretKeyString", this.secretKeyString);
		// console.log("publicKey",this.publicKey);
		// console.log("publicKeyString",this.publicKeyString);	
		// return {keyPair, secretKeyString, publicKeyString}
		return {
			publicKey: Buffer.from(keyPair.publicKey), 
			privateKey: Buffer.from(keyPair.secretKey)
			}
	}

  /**
	 * encrypt
	 * Using Curve25519 , my secret key and their public key to encrypt a message
	 * Convert our secret key and their public key from Ed25519 into the format accepted by Curve25519.
	 * 
	 * @param {*} message 
	 * @param {*} myNonceString 
	 * @param {*} theirPublicKeyString 
	 * @param {*} mySecretKeyString 
	 * @returns 
	 */
	function encrypt(msg, myNonceString, theirPublicKeyString, mySecretKeyString){
		if (!msg) {
			throw new Error("cannot encode null message");
		}
		const theirPublicKeyUint8 = util.decodeBase64(theirPublicKeyString);
    const mySecretKeyUint8 = util.decodeBase64(mySecretKeyString);

		const theirDHPublicKey = ed2curve.convertPublicKey(theirPublicKeyUint8);
		const myDHSecretKey = ed2curve.convertSecretKey(mySecretKeyUint8);		

		const box = nacl.box(
				util.decodeUTF8(msg),
				util.decodeBase64(myNonceString),
				theirDHPublicKey,
				myDHSecretKey
		)
	  const encryptedMessage = util.encodeBase64(box);
	  return encryptedMessage;
	}



	/**
	 * encrypt
	 * 
	 * Using Curve25519 , my secret key and their public key to encrypt a message
	 * Convert our secret key and their public key from Ed25519 into the format accepted by Curve25519.
	 * 
	 * @param {*} encryptedMessage 
	 * @param {*} theirNonceString 
	 * @param {*} theirPublicKeyString 
	 * @param {*} mySecretKeyString 
	 * @returns 
	 */
	function decrypt(encryptedMessage, theirNonceString, theirPublicKeyString, MySecretKeyString){	
		const theirPublicKeyUint8 = util.decodeBase64(theirPublicKeyString);
    const mySecretKeyUint8 = util.decodeBase64(MySecretKeyString);
		// const theirNonceUint8 = util.decodeBase64(theirNonceString);

		const theirDHPublicKey = ed2curve.convertPublicKey(theirPublicKeyUint8);
		const myDHSecretKey = ed2curve.convertSecretKey(mySecretKeyUint8);    
    const nonceUint8 = util.decodeBase64(theirNonceString);
    const boxUint8 = util.decodeBase64(encryptedMessage);

    const payload = nacl.box.open(boxUint8, nonceUint8, theirDHPublicKey, myDHSecretKey );
    const decryptedMessage  = util.encodeUTF8(payload);
		return decryptedMessage ;
	}



	/**
	 * sign
	 * basing ed25519 to sign the message using the secret key
	 * 	 * 
	 * @param {*} message 
	 * @param {*} mySecretKeyString 
	 * @returns 
	 */
	function sign(message, privateKey){
		if (!message) {
			throw new Error("cannot sign null message");
		}
		
    // const mySecretKeyUint8 = util.decodeBase64(privateKey);
		const signedMessage  = nacl.sign(util.decodeUTF8(message), privateKey);	
		console.log("signedMessage: ",signedMessage)
		console.log("signedMessage-buffer: ",Buffer.from(signedMessage))
		const signedMessageString = util.encodeBase64(signedMessage);	
		return Buffer.from(signedMessage);
	}


		/**
	 * verify
	 * Using ed25519 to verify signatrue
	 * 
	 * @param {*} signedMessage 
	 * @param {*} theirPublicKeyString 
	 * @returns 
	 */
function 	verify(signedMessage , publicKey, msg){
		if (!signedMessage) {
			throw new Error("cannot verify null signed message");
		}
		// const theirPublicKeyUint8 = util.decodeBase64(theirPublicKeyString);
		// const signedMessageUint8 = util.decodeBase64(signedMessage);

		const verifiedMessage = nacl.sign.open(signedMessage, publicKey);	
		const verified = util.encodeUTF8(verifiedMessage)
		console.log(msg === verified)
		return msg === verified;
	}




	//产生公钥私钥
	const  {publicKey, privateKey} = genKeyPair();
	console.log("privateKey: ", privateKey)
	console.log("privateKey-hex: ", privateKey.toString('hex'))
	console.log("publicKey: ", publicKey)
	console.log("publicKey-hex: ", publicKey.toString('hex'))
	// 签名
	var msg = "helle tweetnacl!";
  	

	const signedMessage = sign(msg, privateKey);
	console.log("signedMessage: ", signedMessage)

	// // 验证
	const veri = verify(signedMessage, publicKey,msg)
	console.log("verify: ",veri)