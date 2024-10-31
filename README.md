# NIST SP 800-90A Rev. 1 (PHP)

NIST SP 800-90A Rev. 1 HMAC SHA-256 deterministic random bit generator written in PHP.

## Class Diagram 

![class diagram](https://github.com/vasconcedu/nist-sp-800-90a-rev1-php/raw/main/classes.png)

## Description

**Disclaimer: This implementation passes FIPS 140 randomness tests and NIST CAVP tests, yet it was neither tested for nor written bearing criptographic side-channels in mind and most likely _IS_ vulnerable to some sort of side-channel attack. I've written this merely as a pet project, I _AM NOT_ a cryptography engineer and I strongly discourage you from using this in any piece of software deployed in production environments.**

This is an OO PHP implementation of NIST SP 800-90A Rev. 1 (Recommendation for Random Number Generation Using Deterministic Random Bit Generators) suitable for generating PHP session tokens, for instance, amongst other applications. Please refer to https://csrc.nist.gov/Projects/Random-Bit-Generation/publications for detail.

The DRBG herein uses HMAC with SHA-256 and supports 256 bits strength with maximum output length 7500 bits.

Entropy input is obtained using OpenSSL (hence not NIST-approved). 

## Usage

### Library

Use as defined in `example.php`, e.g.:

```php
try {
    
    ...
    
    $drbg = new HMAC_DRBG();
    $drbg->generate(1024);
    $drbg->__destruct();
    
    ...
    
} catch (Exception $e) {
    echo 'Caught exception: ', $e->getMessage(), "\n";
}
```

### Running `example.php`

```bash
$ php example.php
```

### NIST CAVP Tests

```bash
$ bash run-tests.sh
```

## Acknowledgements

Directory ```test/``` contains NIST test vectors for HMAC DRBG implementations. Please refer to https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program.

Please note that even though this implementation passes FIPS 140 randomness tests and NIST CAVP tests, it has not been submitted for official NIST validation.
