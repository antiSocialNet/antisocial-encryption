// Copyright Michael Rhodes. 2017,2018. All Rights Reserved.
// This file is licensed under the MIT License.
// License text available at https://opensource.org/licenses/MIT

var crypto = require('crypto');
var forge = require('node-forge');
var uuid = require('uuid');
var debug = require('debug')('antisocial-encryption');

var algorithm = 'aes192';

/*
	implement Hybrid Cryptosystem used for user to user encryption of messages
	using previously exchanged public keys
*/

/*
	Decrypt a message encrypted with encrypt
	* @param {String} publicKey - public key of recipient
	* @param {String} privateKey - private key of sender
	* @param {String} data - data to encrypt
	* @returns {Object} message - signed and encrypted data
 */

module.exports.encrypt = function encrypt(publicKey, privateKey, stringToEncrypt, contentType) {

	debug('encrypt %s', stringToEncrypt, contentType);

	var password = uuid();

	// sign message with private key
	const sign = crypto.createSign('RSA-SHA256');
	sign.write(stringToEncrypt);
	sign.end();
	var sig = sign.sign(privateKey, 'hex');

	// encrypt message with aes using random password as the key
	var cipher = crypto.createCipher(algorithm, password);
	var encrypted = cipher.update(stringToEncrypt, 'utf8', 'hex');
	encrypted += cipher.final('hex');

	// encrypt random password using public key
	var pass = crypto.publicEncrypt(publicKey, new Buffer(password));

	var message = {
		'data': encrypted,
		'pass': pass,
		'sig': sig,
		'contentType': contentType ? contentType : 'application/json'
	};

	debug('encrypt message %j', message);

	return (message);
};

/*
	Decrypt a message previously encrypted with call to encrypt
	* @param {String} publicKey - public key of sender
	* @param {String} privateKey - private key of recipient
	* @param {Object} message - message object from sender's call to encrypt
	* @returns {Object} { data: decrypted data (if valid), valid: boolean, invalidReason: reason for failure if applicable}
 */

module.exports.decrypt = function decrypt(publicKey, privateKey, message) {

	var data = message.data;
	var sig = message.sig;
	var pass = message.pass;
	var contentType = message.contentType ? contentType : 'application/json';

	debug('decrypt data: %s pass: %j sig: %s', data, pass, sig);

	// decrypt password with private key
	var decryptedPass
	try {
		decryptedPass = crypto.privateDecrypt(privateKey, new Buffer(pass, 'base64')).toString('utf8');
	}
	catch (err) {
		var result = {
			'valid': false,
			'invalidReason': 'decryption error ' + err
		}
		return result;
	}

	// decrypt message using decrypted password

	var decipher = crypto.createDecipher(algorithm, decryptedPass);
	var decrypted = decipher.update(data, 'hex', 'utf8');
	decrypted += decipher.final('utf8');

	// validate signature using public key
	const verify = crypto.createVerify('RSA-SHA256');
	verify.update(decrypted);
	var valid = verify.verify(publicKey, sig, 'hex');

	debug('decrypt valid: %s decrypted: %s', decryptedPass, valid, decrypted);

	var result = {
		'valid': valid,
		'contentType': contentType
	}

	if (valid) {
		result.data = decrypted
	}
	else {
		data.invalidReason = 'signing error';
	}

	return result;
};

/*
 * generate a key pair
 * @param {Function} cb - the callback (err,keypair)
 * @returns {Object} keypair { public: 2048 bit rsa key, private: 2048 bit rsa key }
 */

module.exports.getKeyPair = function getKeyPair(cb) {
	var rsa = forge.pki.rsa;
	rsa.generateKeyPair({
		bits: 2048,
		workers: 2
	}, function (err, pair) {
		if (err) {
			return cb(err);
		}
		var keypair = {
			public: forge.pki.publicKeyToPem(pair.publicKey, 72),
			private: forge.pki.privateKeyToPem(pair.privateKey, 72)
		};
		cb(null, keypair);
	});
}
