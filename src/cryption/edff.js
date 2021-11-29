const nacl = require(“tweetnacl");
const crc = require("crc");
const base32 = require("base32.js")
const isUndefined = require("lodash/isUndefined");
const isNull = require("lodash/isNull");
const isString = require("lodash/isString");
const versionBytes = {
  ed25519PublicKey:  6 << 3, // G
  ed25519SecretSeed: 18 << 3, // S
  preAuthTx:         19 << 3, // T
  sha256Hash:        23 << 3  // X
};
 
//封装一个类，构造函数中生成keypair，提供静态编码解码公钥私钥方法
class Keypair {
    constructor(){
        this.orikeypair = nacl.sign.keyPair();
        this.publicKey = Buffer.from(this.orikeypair.publicKey);
        console.log(this.orikeypair.publicKey);
        this.privateKey = Buffer.from(this.orikeypair.secretKey);
    }
    static encodeCheck(versionByteName, data) {
        if (isNull(data) || isUndefined(data)) {
            throw new Error("cannot encode null data");
        }
        let versionByte = versionBytes[versionByteName];
        if (isUndefined(versionByte)) {
            throw new Error(`${versionByteName} is not a valid version byte name.  expected one of "ed25519PublicKey", "ed25519SecretSeed", "preAuthTx", "sha256Hash"`);
        }
        data  = Buffer.from(data);
        let versionBuffer = Buffer.from([versionByte]);
        let payload       = Buffer.concat([versionBuffer, data]);
        let checksum      = calculateChecksum(payload);
        let unencoded     = Buffer.concat([payload, checksum]);
        return base32.encode(unencoded);
    }
    static decodeCheck(versionByteName, encoded) {
        if (!isString(encoded)) {
          throw new TypeError('encoded argument must be of type String');
        }
        let decoded     = base32.decode(encoded);
        let versionByte = decoded[0];
        let payload     = decoded.slice(0, -2);
        let data        = payload.slice(1);
        let checksum    = decoded.slice(-2);
        if (encoded != base32.encode(decoded)) {
          throw new Error('invalid encoded string');
        }
        let expectedVersion = versionBytes[versionByteName];
        if (isUndefined(expectedVersion)) {
          throw new Error(`${versionByteName} is not a valid version byte name.  expected one of "accountId" or "seed"`);
        }
        if (versionByte !== expectedVersion) {
          throw new Error(`invalid version byte. expected ${expectedVersion}, got ${versionByte}`);
        }
        let expectedChecksum = calculateChecksum(payload);
        if (!verifyChecksum(expectedChecksum, checksum)) {
          throw new Error(`invalid checksum`);
        }
        return Buffer.from(data);
    } 
}
function calculateChecksum(payload) {
  // This code calculates CRC16-XModem checksum of payload
  // and returns it as Buffer in little-endian order.
  let checksum = Buffer.alloc(2);
  checksum.writeUInt16LE(crc.crc16xmodem(payload), 0);
  return checksum;
}
//测试使用
let newKeypair = new Keypair();
console.log(newKeypair.publicKey);
let newPublic = Keypair.encodeCheck("ed25519PublicKey",newKeypair.publicKey);
let newPrivate = Keypair.encodeCheck("ed25519SecretSeed",newKeypair.privateKey);
let publicBuffer = Keypair.decodeCheck("ed25519PublicKey",newPublic);
console.log(newPublic,newPrivate);
