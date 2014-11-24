keccakj
========

Pure Java implementation of Keccak with implementations of
  * SHA3-224,SHA3-256,SHA3-384,SHA3-512 message digests (*FIPS 202 DRAFT*).
  * SHAKE128/SHAKE256 (*FIPS 202 DRAFT*). Can be used in various ways, eg.
    1. As a message digest with variable output length.
    2. As a stream cipher.
    3. As a non-reseedable random generator.
  * LakeKeyak authenticated encryption.
  * Stream ciphers based on SHAKE128/SHAKE256.
  * Secure/Cryptographic ressedable random generators based on the Duplex
   construction.

### Keccakj is licensed under the Apache License, Version 2.0.

#How to use

### Using Keccakj with the Java security API:

#### Installing the security provider dynamically

    import com.github.aelstad.keccakj.provider.KeccakjProvider;
    ...
    Security.addProvider(new KeccakjProvider());

#### Installing the security provider statically
Modify JAVA_HOME/jre/lib/security/java.security and add

    security.provider.N=com.github.aelstad.keccakj.provider.KeccakjProvider

#### MessageDigests:
    import java.security.MessageDigest;
    import com.github.aelstad.keccakj.provider.Constants;

    ...
    MessageDigest md;
    md = MessageDigest.getInstance(Constants.SHA3_224, Constants.PROVIDER);
    md = MessageDigest.getInstance(Constants.SHA3_256, Constants.PROVIDER);
    md = MessageDigest.getInstance(Constants.SHA3_384, Constants.PROVIDER);
    md = MessageDigest.getInstance(Constants.SHA3_512, Constants.PROVIDER);

#### SecureRandoms:
    import java.security.SecureRandom;
    import com.github.aelstad.keccakj.provider.Constants;

    ...
    SecureRandom sr;
    sr = SecureRandom.getInstance(Constants.KECCAK_RND128, Constants.PROVIDER);  
    sr = SecureRandom.getInstance(Constants.KECCAK_RND256, Constants.PROVIDER);

#### Ciphers:
** Note that Cipher use requires the provider to be in a signed and trusted jar. **

    import java.security.Cipher;
    import com.github.aelstad.keccakj.provider.Constants;

    Cipher cipher;
    cipher = Cipher.getInstance(Constants.SHAKE128_STREAM_CIPHER, Constants.Provider);
    cipher = Cipher.getInstance(Constants.SHAKE256_STREAM_CIPHER, Constants.Provider);
    cipher = Cipher.getInstance(Constants.LAKEKEYAK_AUTHENTICATING_STREAM_CIPHER, Constants.Provider);

### Using Keccakj without installing a Java security provider:

### MessageDigests
    import java.security.MessageDigest;
    import com.gituhub.aelstad.keccakj.fips202.*;

    ....
    MessageDigest md = new SHA3_224();
    md = new SHA3_256();
    md = new SHA3_384();
    md = new SHA3_512();
    ...
    AbstractSponge sponge = new Shake128();
    sponge = new Shake256();
    ..
    // absorb data
    sponge.getAbsorbStream().write(..)
    // squeeze digest
    byte[] digest = new byte[whatever-length-you-like]
    sponge.getSqueezeStream().read(digest);
    sponge.reset();

### SecureRandoms
    import java.security.SecureRandom;
    import com.github.aelstad.keccakj.core.DuplexRandom;

    // let capcity be n*64 - 3 for efficiency, with n between [4, 25> for security.
    DuplexRandom dr = new DuplexRandom(capcity);

    // with capacity 253 suitable for session keys
    SecureRandom sr;
    sr  = new com.github.aelstad.keccakj.spi.KeccakRnd128();
    // with capacity 509 suitable for long term keys
    sr = new com.github.aelstad.keccakj.spi.KeccakRnd256();


### Ciphers
    import com.github.aelstad.keccakj.spi.*;
    ...
    CipherInterface ci;
    ci = new Shake128StreamCipher();
    ci = new Shake256StreamCipher();
    ci = new LakeKeyakCipher();

#Typical performance

Single threaded on a i7-4770S

|Algorithm|Speed|
|---------|------|
|SHA3-224|170MB/s|
|SHA3-256|165MB/s|
|SHA3-384|130MB/s|
|SHA3-512|93MB/s|
|LakeKeyak authenticated encryption/decryption|260MB/s|



# Acknowledgments

The test vectors files are copied from https://github.com/gvanas/KeccakCodePackage

The permutation implementation is based on the reference C implementation in https://github.com/gvanas/KeccakCodePackage

# Links

More information can be found:

* on Keccak in general at http://keccak.noekeon.org/
* on Ketje at http://ketje.noekeon.org/
* on Keyak at http://keyak.noekeon.org/
* and on cryptographic sponge functions at http://sponge.noekeon.org/
