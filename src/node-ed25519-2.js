const {
  generateKeyPairSync, 
	createSign,
  createVerify,
	sign,
	verify,
	createPublicKey,
	createPrivateKey
} = require('crypto');
const { publicKey, privateKey } = generateKeyPairSync('ed25519') 


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
// const sig = sign(null, Buffer.from(msg), privateKey);
const sig = sign(null, Buffer.from(message,'utf8'),  privateKey.export({type:'pkcs8',format:'pem'}));
//ERROR 不可以传入der格式
//  const sig = sign(null, Buffer.from(msg),  privateKey.export({type:'pkcs8',format:'der'}));

console.log('sig: ', sig);
console.log('sig-hex: ', sig.toString('base64'));
console.log('sig-hex: ', );
console.log('sig.length: ', sig.length);


// 0. 
const forgePriKey = 'IHNW6AI6UzY2PdX8knd948icE49BKUmUCKWiwTf/N99Pkd1aLlTIYeZYNxt0uxstl3M6D4IvN+NRbl6SLqFyaA=='
const priKey =  Buffer.from(forgePriKey,'base64')
console.log(priKey);

// 1. 使用forge的私钥产生公钥
const pKey = createPublicKey(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICBzVugCOlM2Nj3V/JJ3fePInBOPQSlJlAilosE3/zff
-----END PRIVATE KEY-----`);
// const pKey = createPublicKey(priKey);
// const pKey = createPublicKey(privateKey.export({type:'pkcs8',format:'pem'}));
// const pKey = publicKey.export({type:'spki',format:'pem'})

// 2. 使用forge的base64格式签名signature
const siguature = Buffer.from('YUGnDEDyVPMA01UxlAbzPnC7b92Zuj0ulW1z2onvKx0gTU7zF996XO6wpsco48CbMhYYF1SowQOX/Myif+8EBA==','base64') //!!!!!!!!!!!!!!!!!!!!!!!!!!!注意格式
// const siguature = Buffer.from(sig.toString('base64'),'base64') //!!!!!!!!!!!!!!!!!!!!!!!!!!!注意格式
console.log('signture: ', siguature);

// const ver = verify(null, Buffer.from(msg), publicKey, sig);
const ver = verify(null, Buffer.from(message,'utf8'), pKey, siguature);

//Error 不可以使用der格式
//  const ver = verify(null, Buffer.from(msg), publicKey.export({type:'spki',format:'der'}), sig);

console.log('verify', ver);

// console.log("-------------------------------------------------------------------------")