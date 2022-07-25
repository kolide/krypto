# Krypto

This repository contains libraries to facilitate cross-language
cryptographic messaging.

**TODO:**
- [ ] License should be what?
- [ ] Change name? (`krypto`? `CrossCryptography`?)
- [ ] Some code review

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

Unlike many of our libraries, this is in a dedicated repository. This
was chosen to make it easier to isolate the parts that _must_ be cross
language compatible.
