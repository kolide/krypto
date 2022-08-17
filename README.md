# Krypto

This repository contains libraries to facilitate cross-language
cryptographic messaging between Kolide products.

## Project Layout

This project has a variety of languages all stored in a big pile.
1. It's a gem!
2. It's a go module!

Enjoy!

## FAQ

### 1. But Why?

We work with various languages, and while they support many
cryptography functions, finding the common set functions has a fair
bit of trial and error. These libraries hardcode those settings, and
build additional tools over them.

In isolation, `NaCl` (or `libsodium)` would be a good approach. But
that's not an easy library to bring into our ecosystem at this time.

### 2. Why a dedicated repo?

Unlike many of our libraries, this is in a dedicated repository.

This was chosen to make it easier to isolate the parts that are cross
language compatible, and thus _must_ update in tandem. There is a set
of cross language tests in `cross_language_tests/` designed to check
this. (They are go tests, and can be run as `go test
./cross_language_tests/`)

## Thanks and References

This wouldn't be possible without the work of various people. As code,
blog posts, and stackoverflow posts. 

* Huge thanks to the go crypto maintainers
* https://stelfox.net/blog/2014/calculating-rsa-key-fingerprints-in-ruby/ is a short reference about various bits of fingering printing in ruby
* https://github.com/funny/crypto/blob/master/aes256cbc/aes256cbc.go is an example of AWS-256-CBC mode. While not something needed, it was good background
* Ruby and Go handle AES's `authenticated code` differently. Several good questions discussing that
  - https://stackoverflow.com/questions/68040875/
  - https://stackoverflow.com/questions/68350301
  - https://crypto.stackexchange.com/questions/25249

