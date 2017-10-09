GOTP: golang one-time password tool
===================================

`gotp` is a tool for managing gpg-encrypted [HOTP](https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm) and [TOTP](https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
tokens, the kinds of tokens used for two-factor authentication by services
like AWS, Dropbox, Google, Facebook, etc.

With `gotp`, a user can use their computer and their GPG key as a second factor.
Since it is possible to encrypt a message with multiple GPG keys, it is then also
possible to share an OTP secret between multiple users; for instance, a team
with a single account on a service could enable two-factor authentication and
encrypt the OTP secret with every team member's key.

```
$ gotp
Mon Jul 10 14:10:44 PDT 2017
        aws-dev: 180472
       aws-prod: 837059
        dropbox: 615562
 secret-service: HOTP
```

Usage
-----

`gotp` encrypts tokens with one or more GPG key. Keys can be specified with either
a key's 20-byte fingerprint or with the email associated with the key.

### Enrolling
Enrolling a token is simple. The enroll command takes several parameters:
* `--token`: the name of the token being enrolled (ex: `github`, `dropbox`)
* `--emails`: a comma-separated list of emails identifying GPG keys. The first matching GPG key is used; if in doubt, specify using the key's fingerprint. (ex: `me@company.com,coworker@company.com`)
* `--fingerprints`: a comma-separated list of GPG key fingerprints. The full 20-byte fingerprint is required.

If you are enrolling an HOTP token, then be sure to pass the `--hotp` flag and the `--counter` flag (default: 0).

Examples:
```
$ gotp enroll --fingerprints 2187... --emails username@company.com --token another-service
Paste secret:
Added token another-service successfully with 2 keys!
```

Now, the token is available for use:
```
$ gotp
Mon Jul 10 14:26:49 PDT 2017
 another-service: 961126
```

### HOTP
After enrolling a token as shown above, the current token value can be shown with `increment`.
This also increments the counter by one:

```
$ gotp increment -t hotp-token
Wed Apr 12 12:27:06 PDT 2017
hotp-token: 535293
```

### Deleting
To delete a token:

```
$ gotp delete -t another-service
Are you sure you want to remove token another-service? y/[N] y
Deleting token another-service...
Token deleted successfully!
```

If you wish to remove without prompting, the `--force/-f` parameter removes this check.
The delete command simply removes the directory `$HOME/.otptokens/[tokenname]`.

Serving over HTTP
-----------------
`gotp` comes with an HTTP server. It is designed for using behind some kind of auth proxy
(such as [oauth2_proxy](https://github.com/bitly/oauth2_proxy)) By serving tokens
over authenticated HTTP, a team of people can make use of two-factor authentication
on a shared account *and* revoke access to individuals, without needing to rotate the secret.

To start the HTTP server:
```
$ gotp serve
2017/07/14 16:11:23 Starting HTTP server...
```

In a separate terminal window:
```
$ curl http://localhost:8080/tokens/my-fav-service
279790
```

**Note:** because `gotp` prompts for the GPG key upon attempted decryption of a token,
it will either be necessary to set `gpg-agent` to never forget the key password, or
to use an unencrypted GPG key.

**TODO:** Verify that it doesn't prompt if you use an unecrypted key.

Generating Testing Tokens
-------------------------

OTP secrets are base32 strings. These can be generated from `/dev/random`:

```
$ dd if=/dev/random bs=1 count=40 | base32
72OT4T6Y357MEK3N7W5YPVMZYK4XH36P2JSEHVJIDAETFU2ZALTLPE7RPZNDOXFZ
```

How do I generate a GPG key?
----------------------------

If using `gotp` is your first time using `GPG`, don't fret! GitHub has good
documentation on [how to generate your first key](https://help.github.com/articles/generating-a-new-gpg-key/#generating-a-gpg-key).
After you've generated your key, you can pass the email you generated it
with to the `--emails` option when enrolling a token.