# NIST SP 800-90A Rev. 1 (PHP) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

NIST SP 800-90A Rev. 1 deterministic random bit generator written in PHP.

## Author 

Eduardo Vasconcelos (vasconcedu)

https://tereresecurity.wordpress.com/

I must thank my dear colleague and good friend dbrdem for his contribution. 

## Class Diagram 

![class diagram](https://github.com/vasconcedu/nist-sp-800-90a-rev1-php/raw/main/classes.png)

## Description

**Disclaimer: This implementation passes FIPS 140 randomness tests and NIST CAVP tests, yet it was neither tested for nor written bearing criptographic side-channels in mind and most likely _IS_ vulnerable to some sort of side-channel attack. I've written this merely as a pet project, I _AM NOT_ a cryptography engineer and I strongly discourage you from using this in any piece of software deployed in production environments.**

This is an OO PHP implementation of NIST SP 800-90A Rev. 1 (Recommendation for Random Number Generation Using Deterministic Random Bit Generators) suitable for generating PHP session tokens, for instance, amongst other applications. Please refer to https://csrc.nist.gov/Projects/Random-Bit-Generation/publications for detail.

The DRBG herein uses HMAC with SHA-256 and supports 256 bits strength with maximum output length 7500 bits.

Entropy input is obtained using OpenSSL (hence not NIST-approved). 

## Usage

### Library

Use as defined in example.php, e.g.:

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

### Running example.php

```bash
$ php example.php
```

### Tests

```bash
$ bash run-tests.sh
```

## License 

MIT License

Copyright (c) 2020 vasconcedu

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Acknowledgements

Directory ```test/``` contains NIST test vectors for HMAC DRBG implementations. Please refer to https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program.

Please note that even though this implementation passes FIPS 140 randomness tests and NIST CAVP tests, it has not been submitted for official NIST validation.
