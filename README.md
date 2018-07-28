<img src="https://github.com/antiSocialNet/antiSocial/raw/master/assets/octocloud/logo.jpg" height="200">

# antiSocial

## antisocial-encryption module

Implement Hybrid Cryptosystem used for user to user encryption of messages
using previously exchanged public keys

https://en.wikipedia.org/wiki/Hybrid_cryptosystem

```
npm install antisocial-encryption
```

### Generate a key:

var cryptography = require('antisocial-encryption');

cryptography.getKeyPair(function (err, keypair) {
	if(err) {
		// ...something went wrong...
	}

	kp is an object with 2 properties
	{
		'public': 2048 bit rsa key,
		'private': 2048 bit rsa key
	}

	// now you can do something with the keypair
	// like save it in local data store and hand
	// the public key to the peer you want to exchange
	// encrypted messages with.
});


### Encrypt a message
On the senders side encrypt the message using the recipient public key and the sender private key.

```
var cryptography = require('antisocial-encryption');
var data = JSON.stringify({ 'foo': 'bar' });
message = cryptography.encrypt(publicKeyOfRecipient, privateKeyOfSender, data);
```

The resulting message is an object containing the encrypted data, a signature and an encrypted password which can only be decrypted by the recipient. This message can now be securely transmitted to the intended recipient.

### Decrypt the message
On the recipient side decrypt the message using the sender public key and the recipient private key.

```
var decrypted = cryptography.decrypt(publicKeyOfSender, privateKeyOfRecipient, message);
```

decrypted.valid is false then the error description is in decrypted.invalidReason

if decrypted.valid is true, the decrypted information is in decrypted.data.
