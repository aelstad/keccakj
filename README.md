keccakj
========

Pure Java implementation of Keccak with implementations of
  * SHA3-224,SHA3-256,SHA3-384,SHA3-512 message digests (*FIPS 202 DRAFT*).
  * SHAKE128/SHAKE256 (*FIPS 202 DRAFT*). Can be used in various ways, eg.
    1. A variable output message digest.
    2. A stream cipher.
    3. A non-reseedable random generator.
  * LakeKeyak authenticated encryption.
  * Cryptographic ressedable random generators based on the Duplex construction.

### Licensed under the Apache License, Version 2.0.

#How to use

### As a Java security provider



#Typical performance

Single threaded on a i7-4770S

|Algorithm|Speed|
|---------|------|
|SHA3-224|170MB/s|
|SHA3-256|165MB/s|
|SHA3-384|130MB/s|
|SHA3-512|93MB/s|
|LakeKeyak authenticated encryption|255MB/s|
|LakeKeyak authenticated decryption|269MB/s|



# Acknowledgments

The test vectors files are copied from https://github.com/gvanas/KeccakCodePackage

The permutation implementation is based on the reference C implementation in https://github.com/gvanas/KeccakCodePackage

# Links

More information can be found:

* on Keccak in general at http://keccak.noekeon.org/
* on Ketje at http://ketje.noekeon.org/
* on Keyak at http://keyak.noekeon.org/
* and on cryptographic sponge functions at http://sponge.noekeon.org/
