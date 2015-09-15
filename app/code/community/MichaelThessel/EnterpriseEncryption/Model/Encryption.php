<?php

/**
 * Implements EE pasword hashing for CE.
 */
class MichaelThessel_EnterpriseEncryption_Model_Encryption
{
    const HASH_VERSION_MD5    = 0;
    const HASH_VERSION_SHA256 = 1;
    const HASH_VERSION_LATEST = 1;

    const CIPHER_BLOWFISH     = 0;
    const CIPHER_RIJNDAEL_128 = 1;
    const CIPHER_RIJNDAEL_256 = 2;
    const CIPHER_LATEST       = 2;

    protected $_cipher = self::CIPHER_LATEST;
    protected $_crypts = array();

    protected $_keyVersion;
    protected $_keys = array();

    protected $_iv = '';

    /**
     * @var Mage_Core_Helper_Data
     */
    protected $_helper;

    public function __construct()
    {
        // load all possible keys
        $this->_keys = preg_split('/\s+/s', trim((string)Mage::getConfig()->getNode('global/crypt/key')));
        $this->_keyVersion = count($this->_keys) - 1;
    }

    /**
     * Set helper instance
     *
     * @param Mage_Core_Helper_Data $helper
     * @return Mage_Core_Model_Encryption
     */
    public function setHelper($helper)
    {
        $this->_helper = $helper;
        return $this;
    }

    /**
     * Check whether specified cipher version is supported
     *
     * Returns matched supported version or throws exception
     *
     * @param int $version
     * @return int
     * @throws Exception
     */
    public function validateCipher($version)
    {
        $version = (int)$version;
        if (!in_array($version, array(self::CIPHER_BLOWFISH, self::CIPHER_RIJNDAEL_128, self::CIPHER_RIJNDAEL_256), true)) {
            Mage::throwException('Not supported cipher version');
        }
        return $version;
    }

    /**
     * Generate a [salted] hash.
     *
     * $salt can be:
     * false - a random will be generated
     * integer - a random with specified length will be generated
     * string
     *
     * @param string $password
     * @param mixed $salt
     * @return string
     */
    public function getHash($password, $salt = false)
    {
        if (is_integer($salt)) {
            $salt = $this->_helper->getRandomString($salt);
        }
        return $salt === false ? $this->hash($password) : $this->hash($salt . $password) . ':' . $salt;
    }

    /**
     * Hash a string
     *
     * @param string $data
     * @param int $version
     * @return string
     */
    public function hash($data, $version = self::HASH_VERSION_LATEST)
    {
        if (self::HASH_VERSION_MD5 === $version) {
            return md5($data);
        }
        return hash('sha256', $data);
    }

    /**
     * Validate hash by specified version
     *
     * @param string $password
     * @param string $hash
     * @param int $version
     * @return bool
     */
    public function validateHashByVersion($password, $hash, $version = self::HASH_VERSION_LATEST)
    {
        // look for salt
        $hashArr = explode(':', $hash, 2);
        if (1 === count($hashArr)) {
            return $this->hash($password, $version) === $hash;
        }
        list($hash, $salt) = $hashArr;
        return $this->hash($salt . $password, $version) === $hash;
    }

    /**
     * Validate hash against all supported versions.
     *
     * Priority is by newer version.
     *
     * @param string $password
     * @param string $hash
     * @return bool
     */
    public function validateHash($password, $hash)
    {
        return $this->validateHashByVersion($password, $hash, self::HASH_VERSION_SHA256)
            || $this->validateHashByVersion($password, $hash, self::HASH_VERSION_MD5);
    }

    /**
     * Initialize crypt module if needed
     *
     * By default initializes with latest key and crypt versions
     *
     * @param string $key
     * @return Varien_Crypt_Mcrypt
     */
    protected function _getCrypt($key = null, $cipherVersion = null)
    {
        if (null === $key && null == $cipherVersion) {
            $cipherVersion = self::CIPHER_RIJNDAEL_256;
        }

        if (null === $key) {
            $key = $this->_keys[$this->_keyVersion];
        }
        if (null === $cipherVersion) {
            $cipherVersion = $this->_cipher;
        }
        $cipherVersion = $this->validateCipher($cipherVersion);

        $this->_crypts[$key][$cipherVersion] = Varien_Crypt::factory();
        $this->_crypts[$key][$cipherVersion]->setMode(MCRYPT_MODE_ECB);
        $this->_crypts[$key][$cipherVersion]->setCipher(MCRYPT_BLOWFISH);

        if ($cipherVersion === self::CIPHER_RIJNDAEL_128) {
            $this->_crypts[$key][$cipherVersion]->setCipher(MCRYPT_RIJNDAEL_128);
        } elseif ($cipherVersion === self::CIPHER_RIJNDAEL_256) {
            $this->_crypts[$key][$cipherVersion]->setCipher(MCRYPT_RIJNDAEL_128);
            $this->_crypts[$key][$cipherVersion]->setMode(MCRYPT_MODE_CBC);
            $this->_crypts[$key][$cipherVersion]->setInitVector($this->_iv);
        }
        $this->_crypts[$key][$cipherVersion]->init($key);
        return $this->_crypts[$key][$cipherVersion];
    }

    /**
     * Prepend key and cipher versions to encrypted data after encrypting
     *
     * @param string $data
     * @return string
     */
    public function encrypt($data)
    {
        $crypt = $this->_getCrypt();
        return (MCRYPT_BLOWFISH !== $crypt->getCypher() ? $this->_keyVersion . ':' . $this->_cipher . ':' : '') .
               (MCRYPT_MODE_CBC === $crypt->getMode() ? $crypt->getInitVector() . ':' : '') .
               base64_encode($crypt->encrypt((string)$data));
    }

    /**
     * Look for key and crypt versions in encrypted data before decrypting
     *
     * Unsupported/unspecified key version silently fallback to the oldest we have
     * Unsupported cipher versions eventually throw exception
     * Unspecified cipher version fallback to the oldest we support
     *
     * @param string $data
     * @return string
     */
    public function decrypt($data)
    {
        if ($data) {
            $parts = explode(':', $data, 4);
            $partsCount = count($parts);

            // specified key, specified crypt, specified iv
            if (4 === $partsCount) {
                list($keyVersion, $cryptVersion, $iv, $data) = $parts;
                $this->_iv    = $iv ? $iv : null;
                $keyVersion   = (int)$keyVersion;
                $cryptVersion = self::CIPHER_RIJNDAEL_256;
            }
            // specified key, specified crypt
            elseif (3 === $partsCount) {
                list($keyVersion, $cryptVersion, $data) = $parts;
                $keyVersion   = (int)$keyVersion;
                $cryptVersion = (int)$cryptVersion;
                $this->_iv = null;
            }
            // no key version = oldest key, specified crypt
            elseif (2 === $partsCount) {
                list($cryptVersion, $data) = $parts;
                $keyVersion   = 0;
                $cryptVersion = (int)$cryptVersion;
                $this->_iv = null;
            }
            // no key version = oldest key, no crypt version = oldest crypt
            elseif (1 === $partsCount) {
                $keyVersion   = 0;
                $cryptVersion = self::CIPHER_BLOWFISH;
                $this->_iv = null;
            }
            // not supported format
            else {
                return '';
            }
            // no key for decryption
            if (!isset($this->_keys[$keyVersion])) {
                return '';
            }
            $crypt = $this->_getCrypt($this->_keys[$keyVersion], $cryptVersion);
            return str_replace("\x0", '', trim($crypt->decrypt(base64_decode((string)$data))));
        }
        return '';
    }

    /**
     * Return crypt model, instantiate if it is empty
     *
     * @param string $key
     * @return Varien_Crypt_Mcrypt
     */
    public function validateKey($key)
    {
        return $this->_getCrypt($key);
    }
}
