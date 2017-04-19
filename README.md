GOTP: golang one-time password generation tool
==============================================

`gotp` is a tool for managing gpg-encrypted [HOTP](https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm) and [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
tokens, the kinds of tokens used for two-factor authentication by services
like AWS, Dropbox, Google, Facebook, etc.

The goal of `gotp` is that a user can securely use their computer, along with
their gpg key, as a second factor. Due to the nature of gpg, this comes with the
added benefit that, with some kind of shared storage, the OTP secret could be
shared between multiple users; for instance, a team with a single account on a
service could enable two-factor authentication and then encrypt the secret for
that service with every team member's gpg key.

```
$ gotp
Wed Apr 12 12:15:25 PDT 2017
aws-dev: 798748
aws-prod: 205905
dropbox: 693472
```

Usage
-----

`gotp` currently requires gpg keys to be specified by full fingerprint. To get
the fingerprint of your gpg key, the `--fingerprint` gpg command can be used:

```
$ gpg --fingerprint user@example.com
pub   4096R/6BADE665 2017-01-25 [expires: 2018-07-19]
      Key fingerprint = 9D19 556E 2ED7 60E4 1ACA  825D 9026 84E8 9DBC F765
```

To add a token to `gotp`:

```
$ gotp enroll --fingerprints 9D19556E2ED760E41ACA825D902684E89DBCF765 --token service-name
Paste secret:
2017/04/12 12:25:13 encrypting with key 9d19556e2ed760e41aca825d902684e89dbcf765
```

Now, the token is available for use:
```
$ gotp
Wed Apr 12 12:27:06 PDT 2017
service-name: 153439
```

To enroll an `hotp` token, specify `--hotp` and the `--count`:

```
$ gotp enroll --fingerprints 9D19556E2ED760E41ACA825D902684E89DBCF765 --token hotp-token --hotp --counter 1
```

To view the value of an HOTP token, use `increment`. This also increments the counter by one:

```
$ gotp increment -t hotp-token
Wed Apr 12 12:27:06 PDT 2017
hotp-token: 535293
```

Generating Testing Tokens
-------------------------

OTP secrets are base32 strings. These can be generated from `/dev/random`:

```
$ dd if=/dev/random bs=1 count=40 | base32
72OT4T6Y357MEK3N7W5YPVMZYK4XH36P2JSEHVJIDAETFU2ZALTLPE7RPZNDOXFZ
```
