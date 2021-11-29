const {
  generateKeyPairSync, 
	createSign,
  createVerify,
	sign,
	verify,
	createPublicKey,
	createPrivateKey,
	createHash
} = require('crypto');
const { publicKey, privateKey } = generateKeyPairSync('ed25519') 

// const priKey = createPrivateKey(privateKey);

// privateKey 长度48 base64编码？
console.log('--------------------------------privateKey--------------------------------------')
console.log('privateKey: ', privateKey);
console.log('privateKey.asymmetricKeyDetails: ', privateKey.asymmetricKeyDetails);
console.log('privateKey.asymmetricKeyType: ', privateKey.asymmetricKeyType);
// console.log('privateKey.export: ', privateKey.export({type:'pkcs8',format:'der'}));
// console.log('privateKey.export: ', privateKey.export({type:'pkcs8',format:'jwk'}));
console.log('privateKey.export-pem: \n', privateKey.export({type:'pkcs8',format:'pem'}));
console.log('\nprivateKey.export-der: ', privateKey.export({type:'pkcs8',format:'der'}));
console.log('\nprivateKey.export-der-hex: ', privateKey.export({type:'pkcs8',format:'der'}).toString('hex'));
console.log('\nprivateKey.export-der-base64: ', privateKey.export({type:'pkcs8',format:'der'}).toString('base64'));
console.log('privateKey.export-der: ', privateKey.export({type:'pkcs8',format:'der'}).length);
console.log("privateKey.symmetricKeySize: ",privateKey.symmetricKeySize);
console.log("privateKey.type: ", privateKey.type );


// publicKey 长度44 base64编码？
console.log("")
console.log("---------------------------------publicKey--------------------------------------")
console.log('publicKey: ', publicKey)
console.log('publicKey.asymmetricKeyDetails: ', publicKey.asymmetricKeyDetails);
console.log('publicKey.asymmetricKeyType: ', publicKey.asymmetricKeyType);
console.log('publicKey.export-pem: \n', publicKey.export({type:'spki',format:'pem'}));
console.log('publicKey.export-der: ', publicKey.export({type:'spki',format:'der'}));
console.log('publicKey.export-der-hex: ', publicKey.export({type:'spki',format:'der'}).toString('hex'));
console.log('publicKey.export-der: ', publicKey.export({type:'spki',format:'der'}).length);
console.log("publicKey.symmetricKeySize: ",publicKey.symmetricKeySize);
console.log("publicKey.type: ", publicKey.type );
//从privateKey 创建 publicLKey
const pubKey = createPublicKey(privateKey);
console.log('publicKeyFromPrivateKey.export:', pubKey.export({type:'spki',format:'der'}));


console.log("")
console.log("----------------------------------sign---------------------------------------")

/*
*sign verify 中接收的publicKey privateKey格式
*	1. 接收：原始格式或者pem格式 
* 2. 不接受：der(Buffer)
*
*/

const message = "hello world!";

// hash-------------------------------------------------
var hash;
// hash = crypto.createHash('md5');
// hash = crypto.createHash('sha1');
hash = createHash('sha256');
// const hash = crypto.createHash('sha512');

// 可任意多次调用update():
hash.update(message);
const md =  hash.digest('hex');
console.log("hash: ", md); // 7e1977739c748beac0c0fd14fd26a544

//sign-----------------------------------------------------
// const sig = sign(null, Buffer.from(msg), privateKey);
// const sig = sign(null, Buffer.from(message),  privateKey.export({type:'pkcs8',format:'pem'}));
const sig = sign(null, Buffer.from(md),  privateKey.export({type:'pkcs8',format:'pem'}));
//ERROR 不可以传入der格式
//  const sig = sign(null, Buffer.from(message),  privateKey.export({type:'pkcs8',format:'der'}));

console.log('sig: ', sig);
console.log('sig-hex: ', sig.toString('hex'));
console.log('sig.length: ', sig.length);

// const ver = verify(null, Buffer.from(message), publicKey, sig);
// const ver = verify(null, Buffer.from(message), publicKey.export({type:'spki',format:'pem'}), sig);
const ver = verify(null, Buffer.from(md), publicKey.export({type:'spki',format:'pem'}), sig);

//Error 不可以使用der格式
//  const ver = verify(null, Buffer.from(message), publicKey.export({type:'spki',format:'der'}), sig);

console.log('verify', ver);

// console.log("-------------------------------------------------------------------------")