// crypto 提供通用的加密和哈希算法
const crypto = require('crypto');

//1. md5算法
const hash = crypto.createHash('md5');
// const hash = crypto.createHash('sha1');
// const hash = crypto.createHash('sha256');
// const hash = crypto.createHash('sha512');

// 可任意多次调用update():
hash.update('Hello, world!');
hash.update('Hello, nodejs!');

console.log(hash.digest('hex')); // 7e1977739c748beac0c0fd14fd26a544


//2. hmac算法，需要一个秘钥，可以把Hmac理解为用随机数“增强”的哈希算法
const hmac = crypto.createHmac('sha256', 'secret-key');

hmac.update('Hello, world!');
hmac.update('Hello, nodejs!');

console.log(hmac.digest('hex')); // 80f7e22570...



//3. AES对称加密算法，加解密都用同一个密钥；AES有很多不同的算法，如aes192，aes-128-ecb，aes-256-cbc等
function aesEncrypt(data, key) {
    const cipher = crypto.createCipher('aes192', key);
    var crypted = cipher.update(data, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
}

function aesDecrypt(encrypted, key) {
    const decipher = crypto.createDecipher('aes192', key);
    var decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

var data = 'Hello, this is a secret message!';
var key = 'Password!';
var encrypted = aesEncrypt(data, key);
var decrypted = aesDecrypt(encrypted, key);

console.log('Plain text: ' + data);
console.log('Encrypted text: ' + encrypted);
console.log('Decrypted text: ' + decrypted);

// 4.Diffie-Hellman DH算法是一种密钥交换协议，它可以让双方在不泄漏密钥的情况下协商出一个密钥来.


