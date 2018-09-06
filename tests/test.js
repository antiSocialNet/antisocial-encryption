var assert = require('assert');
var expect = require('expect.js');
var cryptography = require('../index.js');

describe('cryptography', function () {
	this.timeout(10000);

	var pair1;
	var pair2;
	var pair3;

	var message;

	it('should be able to generate key pair 1 (peer 1)', function (done) {
		cryptography.getKeyPair(function (err, kp) {
			expect(err).to.be(null);
			pair1 = kp;
			done();
		})
	});

	it('should be able to generate key pair 2 (peer 2)', function (done) {
		cryptography.getKeyPair(function (err, kp) {
			expect(err).to.be(null);
			pair2 = kp;
			done();
		})
	});

	it('should be able to generate key pair 3 (peer 3)', function (done) {
		cryptography.getKeyPair(function (err, kp) {
			expect(err).to.be(null);
			pair3 = kp;
			done();
		})
	});

	it('peer 1 should be able to encrypt data for peer 2', function (done) {
		message = cryptography.encrypt(pair2.public, pair1.private, JSON.stringify({
			'foo': 'bar'
		}));
		done();
	});

	it('peer 2 should be able to decrypt data from peer 1', function (done) {
		var decrypted = cryptography.decrypt(pair1.public, pair2.private, message);
		expect(decrypted).to.be.an('object');
		expect(decrypted.valid).to.equal(true);
		expect(decrypted.contentType).to.equal('application/json');
		expect(JSON.parse(decrypted.data).foo).to.equal('bar');
		done();
	});

	it('peer 3 should not be able to decrypt data from peer 1 (key error)', function (done) {
		var decrypted = cryptography.decrypt(pair1.public, pair3.private, message);
		expect(decrypted).to.be.an('object');
		expect(decrypted.valid).to.equal(false);
		done();
	});

	it('peer 2 should not be able to decrypt data from peer 1 (signature error)', function (done) {
		message.sig = 'bad sig';
		var decrypted = cryptography.decrypt(pair1.public, pair2.private, message);
		expect(decrypted).to.be.an('object');
		expect(decrypted.valid).to.equal(false);
		done();
	});
});
