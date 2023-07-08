# AES CTF Tool

This is an all-in-one solution designed to automate various block cipher (e.g. AES) challenges typically encountered in Capture The Flag (CTF) competitions.

It has the following features:
* Detect Block Cipher Mode used
* Detect Padding Method
* Detect IV Reuse
* Detect Block Size
* Attack using common attacks (e.g. Chosen Plaintext or Padding Oracle)
* Easily extendible

## Usage
A file similar to `main.py` must be created. `init_server` and `encrypt` must be implemented.

### init_server
This method must return an object/process/handle that can be used to encrypt/decrypt data.

### encrypt
This method must be implemented such that it uses the process returned from `init_server` and encrypts it. It **must** return a hex string that is the result of the encryption.

### decrypt
This method is not necessary to be implemented, unless you're running a Padding Oracle attack.


After these methods have been implemented, you start the detector by running `begin()` on the newly created instance of `BCDetector`
