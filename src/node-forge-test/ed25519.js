const forge= require('../vendor/node-forge')
var ed25519 = forge.pki.ed25519;

var keypair;
var keyType;
keyType = 'ed25519'
 
keypair = ed25519.generateKeyPair();

// privateKey 长度44 base64编码？
console.log("")
console.log("---------------------------------privateKey--------------------------------------")
console.log('privateKey: ', keypair.privateKey)
console.log('privateKey-hex: ', keypair.privateKey.toString('hex'))
console.log('privateKey-base64: ', keypair.privateKey.toString('base64'))
console.log('privateKey-hex-length: ', keypair.privateKey.toString('hex').length)
// console.log('privateKey-binary: ', keypair.privateKey.toString('binary'))
// console.log('privateKey: ', forge.pki.privateKeyInfoToPem(keypair.privateKey.toString('hex')));



// publicKey 长度44 base64编码？
console.log("")
console.log("---------------------------------publicKey--------------------------------------")
console.log('publicKey: ',  keypair.publicKey)
console.log('publicKey-base64-base64: ',  Buffer.from(keypair.publicKey.toString('base64'),'base64'))
console.log('publicKey-base64: ',  keypair.publicKey.toString('base64'))
console.log('publicKey-hex: ',  keypair.publicKey.toString('hex'))
console.log('publicKey-hex-ength: ',  keypair.publicKey.toString('hex').length)
// console.log('publicKey-binary: ',  keypair.publicKey.toString('binary'))


console.log("")
console.log("---------------------------------sign------------------------------------------")
/*
*sign verify 中
* 1.publicKey privateKey格式
*	--a. 接收：der(Buffer)
* --b. 不接受：base64、 hex、binary
*
* 2. 哈希值 
* * message Buffer类型参数
*  --a. Buffer.from(message,'binary') //可以
*  --b. Buffer.from(message,'utf8')   //可以
*  --c. Buffer.from(message,'utf8')   //不可以，长度为0
*  --d. "hello world!" //不可以
*
* * md csr.md类型参数
*  --a.  
*/
let message;
// message = "hello world!"; //不可以，不接受此格式 
// message = Buffer.from("hello world!",'binary');
// message = Buffer.from("hello world!",'utf8');

message = Buffer.from("hello world!",'hex');// 不可以，buffer长度为0  

console.log("Buffer.from(message,'binary')",Buffer.from("hello world!",'binary'))
// Buffer.from(message,'binary') <Buffer 68 65 6c 6c 6f 20 77 6f 72 6c 64 21>
console.log("Buffer.from(message,'utf8')",Buffer.from("hello world!",'utf8'))
// Buffer.from(message,'utf8') <Buffer 68 65 6c 6c 6f 20 77 6f 72 6c 64 21>
console.log("Buffer.from(message,'hex')",Buffer.from("hello world!",'hex'))
// Buffer.from(message,'hex') <Buffer >????????????????????????????????长度为零？？？？？？？？？？？？？？？？？？？？？？？

signature = ed25519.sign({
	// also accepts a forge ByteBuffer or Uint8Array
	// md: message, //不可以，只可以传递
	message: message,
	privateKey: keypair.privateKey
});
console.log('signature: ', signature)
console.log('signature-base64: ', signature.toString('base64'))
// console.log('signature-hex: ', signature.toString('hex'))
// console.log('signature-hex: ', signature.toString('binary'))

verified = ed25519.verify({
	// also accepts a forge ByteBuffer or Uint8Array
	message: message,
	// node.js Buffer, Uint8Array, forge ByteBuffer, or binary string
	signature: signature,
	// node.js Buffer, Uint8Array, forge ByteBuffer, or binary string
	publicKey: keypair.publicKey
});

console.log('verified: ', verified)

