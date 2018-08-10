

const crypto = require('crypto');

const algorithm = 'aes-256-ctr';
const iv = crypto.randomBytes(16);
const masterkey = "abhishek_is-great"

var salt = crypto.randomBytes(64);
const hash = crypto.createHash("sha1");
hash.update(salt);
var secret = crypto.pbkdf2Sync(masterkey, salt, 2145, 32, 'sha512');

module.exports = {
    
    encrypt(text) {
        let cipher = crypto.createCipher(algorithm, secret)
        let crypted = cipher.update(text,'utf8','hex')
        crypted += cipher.final('hex');
        return crypted;
    },
    
    decrypt(text) {
        let decipher = crypto.createDecipher(algorithm, secret);
        let dec;
        try {
            dec = decipher.update(text,'hex','utf8');
            dec += decipher.final('utf8');
            return dec ? dec : text;
        }
        catch (err) {
            return text;
        }
    },


    // IV versions

    encryptIV(text) {
        console.log( iv, Buffer.from('abhishek_is-great',32) );
        let cipher = crypto.createCipheriv(algorithm, secret, iv)
        let crypted = cipher.update(text,'utf8','hex')
        crypted += cipher.final('hex');
        return crypted;
    },
    
    decryptIV(text) {
        let decipher = crypto.createDecipheriv(algorithm, secret, iv);
        let dec;
        try {
            dec = decipher.update(text,'hex','utf8');
            dec += decipher.final('utf8');
            return dec ? dec : text;
        }
        catch (err) {
            return text;
        }
    }

};
