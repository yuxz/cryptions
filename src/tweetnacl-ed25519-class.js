const nacl = require('tweetnacl');
const util = require('tweetnacl-util');
const ed2curve = require('ed2curve');
const isUndefined = require("lodash/isUndefined");
const isNull = require("lodash/isNull");
const isString = require("lodash/isString");

/**
 * Curve25519/Ed25519/X25519  椭圆曲线加密 / 签名 /密钥交换算法
 * 
 * 秘钥交换： 我的私钥 + 对方公钥 = 秘钥 
 * 加密：明文 + 秘钥 = 密文 + 秘钥 = 明文
 * 签名：明文 + 私钥 = 签名 + 公钥 = 验证 + 明文 
 * 
 */
module.exports = class Cryption{

	/**
	 * constructor
	 * 
	 * construct Cryption
	 */
	 constructor(){
		// // Generates new random key pair for signing
		// this.keyPair = nacl.sign.keyPair();
		
		// // need to store secretKeyString in browser
		// this.secretKey = this.keyPair.secretKey;
		// this.secretKeyString = util.encodeBase64(this.keyPair.secretKey);

		// // need to share publicKeyString with peers
		// this.publicKey = this.keyPair.publicKey;
		// this.publicKeyString = util.encodeBase64(this.keyPair.publicKey);
    
		// // 
		// this.nonce = nacl.randomBytes(24);
		// this.nonceString = util.encodeBase64(this.nonce);

		// // console.log("secretKey", this.secretKey);
		// console.log("secretKeyString", this.secretKeyString);
		// // console.log("publicKey",this.publicKey);
		// console.log("publicKeyString",this.publicKeyString);
		// // console.log("nonce", this.nonce);
		// console.log("nonceString", this.nonceString);
	}

	/**
	 * genKeyPair
	 * 
	 * Basing ed25519 to generate key pair
	 */
  genKeyPair(){
		// Generates new random key pair for signing
		const keyPair = nacl.sign.keyPair();
				
		// need to store secretKeyString in browser
		const secretKey = this.keyPair.secretKey;
		const secretKeyString = util.encodeBase64(keyPair.secretKey);

		// need to share publicKeyString with peers
		const publicKey = this.keyPair.publicKey;
		const publicKeyString = util.encodeBase64(keyPair.publicKey);		

		// console.log("secretKey", this.secretKey);
		// console.log("secretKeyString", this.secretKeyString);
		// console.log("publicKey",this.publicKey);
		// console.log("publicKeyString",this.publicKeyString);	
		return {keyPair, secretKeyString, publicKeyString}
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
	encrypt(msg, myNonceString, theirPublicKeyString, mySecretKeyString){
		if (isNull(msg) || isUndefined(msg)) {
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
	decrypt(encryptedMessage, theirNonceString, theirPublicKeyString, MySecretKeyString){	
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
	sign(message, mySecretKeyString){
		if (isNull(message) || isUndefined(message)) {
			throw new Error("cannot sign null message");
		}
		
    const mySecretKeyUint8 = util.decodeBase64(mySecretKeyString);
		const signedMessage  = nacl.sign(util.decodeUTF8(message), mySecretKeyUint8);	
		const signedMessageString = util.encodeBase64(signedMessage);	
		return signedMessageString;
	}


		/**
	 * verify
	 * Using ed25519 to verify signatrue
	 * 
	 * @param {*} signedMessage 
	 * @param {*} theirPublicKeyString 
	 * @returns 
	 */
	verify(signedMessage , theirPublicKeyString){
		if (isNull(signedMessage) || isUndefined(signedMessage)) {
			throw new Error("cannot verify null signed message");
		}
		const theirPublicKeyUint8 = util.decodeBase64(theirPublicKeyString);
		const signedMessageUint8 = util.decodeBase64(signedMessage);

		var verifiedMessage = nacl.sign.open(signedMessageUint8, theirPublicKeyUint8);	
		const verifiedMessageString = util.encodeBase64(verifiedMessage);		
		return verifiedMessageString;
	}

}
