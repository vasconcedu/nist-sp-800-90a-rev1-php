<?php

abstract class DRBG {

    const // (All in bits)
        STRENGTH = 256, // Generator strength, since SHA-256 + HMAC => 256 bits
                            // as defined by NIST SP 800-57 Part 1 Rev. 4 (5.6.1)
        MAXGEN = 10000, // Maximum calls to generate before reseed
        MAXBIT = 7500, // Maximum output string length
        MAXPSTR = 256, // Maximum personalization string length
        MAXAINPUT = 256 // Maximum additional input length
    ;
    
    // __getEntropyInput
    // Returns cryptographically safe entropy string. Depends on OpenSSL and throws
    // an exception if no safe algorithm is available locally. 
    // Arguments:
    //  $len: desired entropy length
    // Returns:
    //  Entropy string with $len bits
    public static function __getEntropyInput($len) {
        $len = $len / 8; // e.g. 256 bits / 8 = 32 bytes
        
        // Use OpenSSL to get entropy: works alright, but not NIST SP 800-90A-compliant
        $entropy = openssl_random_pseudo_bytes($len, $strong);
        if ($strong) {
           return $entropy;
        } else {
           throw new Exception('No cryptographically strong algorithm is available.');
        } 
    }
    
    // __construct
    // Instantiates a DRBG object (with a call to instantiate)
    // Arguments:
    //  $predictionResistanceFlag: whether or not DRBG instance employs prediction resistance
    //  $personalizationString: personalization string to use (up to self::MAXPSTR bits)
    //  $test: for testing purposes, this flag indicates whether NIST test vector 
    //      parameters are being used to instantiate the object
    //  $testEntropy: test entropy in case instantiation is used for testing
    //  $testNonce: test nonce in case instantiation is used for testing
    // Returns:
    //  Nothing
    public function __construct($predictionResistanceFlag=TRUE, $personalizationString=NULL, $test=FALSE, $testEntropy=NULL, $testNonce=NULL) {
        $this->instantiate($predictionResistanceFlag, $personalizationString, $test, $testEntropy, $testNonce);
    }
    
    // uninstantiate
    // Destroys a DRBG instance with a call to uninstantiate
    // Arguments:
    //  Nothing
    // Returns:
    //  Nothing
    public function __destruct() {
        $this->uninstantiate();
    }
    
    // instantiateAlgorithm
    // Abstract method to be implemented by child class. Changes DRBG state so as to 
    //  instantiate a new generator. Called by parent class within instantiate.
    // Arguments:
    //  $entropy: entropy
    //  $nonce: nonce
    //  $personalizationString: as defined in __construct
    // Returns:
    //  Nothing
    abstract protected function instantiateAlgorithm($entropy, $nonce, $personalizationString);
    
    // reseedAlgorithm
    // Abstract method to be implemented by child class. Changes DRBG state so as to 
    //  reseed generator. Called by parent class within reseed.
    // Arguments:
    //  $entropy: entropy
    //  $additionalInput: additional input string provided by user application. Limited
    //      by self::MAXAINPUT
    // Returns:
    //  Nothing
    abstract protected function reseedAlgorithm($entropy, $additionalInput);
    
    // generateAlgorithm
    // Abstract method to be implemented by child class. Uses DRBG state so as to 
    //  generate a pseudorandom bit sequence. Called by parent class within generate.
    // Arguments:
    //  $requestedNumberOfBits: number of bits in pseudorandom outpur string.
    //      Limited by self::MAXBIT
    //  $additionalInput: additional input string provided by user application. Limited
    //      by self::MAXAINPUT
    // Returns:
    //  Pseudorandom bit string output or error string, to be handled by caller parent
    abstract protected function generateAlgorithm($requestedNumberOfBits, $additionalInput);
    
    // uninstantiateAlgorithm
    // Abstract method to be implemented by child class. Finishes DRBG instance.
    //  Sets DRBG parameters back to original values.
    // Arguments:
    //  Nothing
    // Returns:
    //  Nothing
    abstract protected function uninstantiateAlgorithm();
    
    // instantiate
    // Properly checks input parameters and calls child method instantiateAlgorithm
    //  so as to instantiate a pseudorandom bit generator 
    // Arguments:
    //  $predictionResistanceFlag: whether or not DRBG instance employs prediction resistance
    //  $personalizationString: personalization string to use (up to self::MAXPSTR bits)
    //  $test: for testing purposes, this flag indicates whether NIST test vector 
    //      parameters are being used to instantiate the object
    //  $testEntropy: test entropy in case instantiation is used for testing
    //  $testNonce: test nonce in case instantiation is used for testing
    // Returns:
    //  Nothing
    private function instantiate($predictionResistanceFlag, $personalizationString, $test, $testEntropy, $testNonce) {
        
        if (!$test) {
        
            $entropy = self::__getEntropyInput(self::STRENGTH);
            $nonce = self::__getEntropyInput(self::STRENGTH / 2);
            
        } else {
        
            if ($testEntropy == NULL or $testNonce == NULL) {
                throw new Exception('Need entropy and nonce for test.');
            }
            
            $entropy = hex2bin($testEntropy);
            $nonce = hex2bin($testNonce);
        }
        
        if (strlen($personalizationString) * 4 > self::MAXPSTR) {
            throw new Exception('Personalization string exceeds maximum length.');
        }
        
        $this->instantiateAlgorithm($entropy, $nonce, hex2bin($personalizationString));
    }
    
    // uninstantiate
    // Properly uninstantiates DRBG object with a call to child method uninstantiateAlgorithm
    // Arguments:
    //  Nothing
    // Returns:
    //  Nothing
    private function uninstantiate() {
        $this->uninstantiateAlgorithm();
    }
    
    public function reseed($additionalInput=NULL, $testEntropy=NULL) {
        
        if (strlen($additionalInput) * 4 > self::MAXAINPUT) {
            throw new Exception('Additional input exceeds maximum length');
        }
        
        if($testEntropy == NULL) {
            $entropy = self::__getEntropyInput(self::STRENGTH);
        } else {
            $entropy = hex2bin($testEntropy);
        }
        
        $this->reseedAlgorithm($entropy, hex2bin($additionalInput));
    }
    
    // generate
    // Calls child method generateAlgorithm so as to generate a pseudorandom output
    //  according to the given parameters. Furthermore, checks input parameters and
    //  handles error returned by child in case reseeding is needed
    // Arguments:
    //  $requestedNumberOfBits: desired output pseudorandom string length
    //  $additionalInput: additional input string provided by user application, limited
    //      by self::MAXAINPUT
    //  $predictionResistanceFlag: flags whether prediction resistance is used
    //  $testEntropyPredictionResistance: entropy for prediction resistance in case 
    //      call is a test
    // Returns:
    //  Pseudorandom string with $requestedNumberOfBits bits
    public function generate($requestedNumberOfBits, $additionalInput=NULL, $predictionResistanceFlag=FALSE, $testEntropyPredictionResistance=NULL) {
        if ($requestedNumberOfBits > self::MAXBIT) {
            throw new Exception('Requested number of bits exceeds maximum supported.');
        }
        
        if (strlen($additionalInput) * 4 > self::MAXAINPUT) {
            throw new Exception('Additional input exceeds maximum length');
        }
        
        if ($predictionResistanceFlag == TRUE) {
            $this->reseed($additionalInput, $testEntropyPredictionResistance);
            $additionalInput = NULL;
        }
        
        $genOutput = $this->generateAlgorithm($requestedNumberOfBits, hex2bin($additionalInput));
        
        if ($genOutput == 'Instantiation can no longer be used.') {
            $this->reseed($additionalInput);
            $additionalInput = NULL;
            $genOutput = $this->generateAlgorithm($requestedNumberOfBits, $additionalInput);
        }
        
        return $genOutput;
    }
}

class HMAC_DRBG extends DRBG {

    const // (In bits)
        OUTLEN = 256 // Algorithm output length (SHA-256 here)
    ;

    private $V; // Secret
    private $K; // Secret
    private $reseedCounter; // Counts calls to generateAlgorithm, bound by
                            // self::MAXGEN in parent class
    
    // instantiateAlgorithm
    // See docs in parent class
    protected function instantiateAlgorithm($entropy, $nonce, $personalizationString) {
        $seed = $entropy . $nonce . $personalizationString;
        $this->K = str_repeat("\x00", self::OUTLEN / 8);
        $this->V = str_repeat("\x01", self::OUTLEN / 8);
        $this->update($seed);
        $this->reseedCounter = 1;
        
    }
    
    // uninstantiateAlgorithm
    // See docs in parent class
    protected function uninstantiateAlgorithm() {
        $this->V = NULL;
        $this->K = NULL;
        $this->reseedCounter = NULL;
    }
    
    // generateAlgorithm
    // See docs in parent class
    protected function generateAlgorithm($requestedNumberOfBits, $additionalInput) {
        if ($this->reseedCounter > self::MAXGEN) {
            return 'Instantiation can no longer be used.';
        }
        
        if ($additionalInput != NULL) {
            $this->update($additionalInput);
        }
        
        $temp = '';
        
        while (strlen($temp) < $requestedNumberOfBits / 8) {
            $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
            $temp = $temp . $this->V;
        }
        
        $genOutput = substr($temp, 0, ($requestedNumberOfBits / 8));
        
        $this->update($additionalInput);
        
        $this->reseedCounter = $this->reseedCounter + 1;
        
        return $genOutput;
    }
    
    // reseedAlgorithm
    // See docs in parent class
    protected function reseedAlgorithm($entropy, $additionalInput) {
        $seed = $entropy . $additionalInput;
        $this->update($seed);
        $this->reseedCounter = 1;
    }
    
    // update
    // Generates new values for V and K using SHA-256 HMAC
    // Arguments:
    //  $providedData: binary string to be appended to V for generating new K state
    // Returns:
    //  Nothing, but changes states of K and V
    private function update($providedData) {
        $this->K = hash_hmac('sha256', $this->V . "\x00" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
        
        if ($providedData == NULL) {
            return;
        }
        
        $this->K = hash_hmac('sha256', $this->V . "\x01" . $providedData, $this->K, TRUE);
        $this->V = hash_hmac('sha256', $this->V, $this->K, TRUE);
    }

}

?>
