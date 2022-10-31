
// encryption in node js
const crypto = require('crypto')

const algorithm = 'aes-256-ctr'
const secretKey = 'vOVH6sdmpNWjRRIqCc7rdxs01lwHzfr3'

const encrypt = text => {
  const iv = crypto.randomBytes(16)

  const cipher = crypto.createCipheriv(algorithm, secretKey, iv)

  const encrypted = Buffer.concat([cipher.update(text), cipher.final()])

  return {
    iv: iv.toString('hex'),
    content: encrypted.toString('hex')
  }
}

const decrypt = hash => {
  const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(hash.iv, 'hex'))

  const decrpyted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'hex')), decipher.final()])

  return decrpyted.toString()
}

let result=(encrypt("123123"))
console.log(result)
let text=decrypt(result)
console.log(text)


// encryption in node js

import CryptoJS from "crypto-js";

let word = "123123";
let key = process.env.ENCRYPT_KEY;
key = CryptoJS.enc.Utf8.parse(key);

let iv = process.env.ENCRYPT_IV;
iv = CryptoJS.enc.Utf8.parse(iv);

// need to copy encryption line to file. In my case export doesnot work
export const encryptPassword=(text)=>{
    let encrypted = CryptoJS.AES.encrypt(text, key, { iv: iv });
    encrypted = encrypted.toString();
    return encrypted
}

// need to copy encryption line to file. In my case export doesnot work
export const decryptPassword=(encryption)=>{
    let decrypted = CryptoJS.AES.decrypt(encryption, key, { iv: iv });
    decrypted = decrypted.toString(CryptoJS.enc.Utf8);
    return decrypted
}