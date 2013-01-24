<?php
/**
 * Auth Cookie Storage for Zend Framework 1.x
 *
 * @category   Zend
 * @package    Zend_Auth
 * @subpackage Zend_Auth_Storage
 * @copyright  Oleg Kunitsyn (https://github.com/OlegKunitsyn)
 * @license    Apache License
 * @version    $Rev 1.1$
 */

/**
 * @see Zend_Auth_Storage_Interface
 */
require_once 'Zend/Auth/Storage/Interface.php';

/**
 * 
 * 
 * @category   Zend
 * @package    Zend_Auth
 * @subpackage Zend_Auth_Storage
 * @copyright  Oleg Kunitsyn (https://github.com/OlegKunitsyn)
 * @license    Apache License
 */
class Auth_Storage_Cookie implements Zend_Auth_Storage_Interface
{
    /**
     * Default name of the cookie for the public key
     */
    const KEY_COOKIE_NAME_DEFAULT = '_k';

    /**
     * Default name of the cookie for the value
     */
    const VALUE_COOKIE_NAME_DEFAULT = '_v';
    
    /**
     * Default cipher
     */
    const CIPHER_DEFAULT = MCRYPT_RIJNDAEL_128;
    
    /**
     * Decrypted cookies
     * 
     * @var mixed
     */
    protected $_cookie = null;

    /**
     * Public key
     * 
     * @var string
     */
    protected $_publicKey = null;

    /**
     * Secret key
     * 
     * @var string
     */
    protected $_secretKey = null;

    /**
     * Name of the cookie for the public key
     *
     * @var string
     */
    protected $_keyCookieName = null;

    /**
     * Name of the cookie for the value
     *
     * @var string
     */
    protected $_valueCookieName = null;
    
    /**
     * Cipher
     *
     * @var string
     */
    protected $_cipher = null;
    
    /**
     * Lifetime of the public key
     *
     * @var int
     */
    protected $_keyLifetime = 0;
    
    /**
     * Initializes storage
     *
     * @param  string $secretKey
     * @param  string $keyCookieName
     * @param  string $valueCookieName
     * @param  string $cipher
     * @param  int $keyLifetime
     * @return void
     */
    public function __construct($secretKey, 
        $keyCookieName = self::KEY_COOKIE_NAME_DEFAULT,
        $valueCookieName = self::VALUE_COOKIE_NAME_DEFAULT,
        $cipher = self::CIPHER_DEFAULT,
        $keyLifetime = null)
    {
        $this->_secretKey = $secretKey;
        $this->_keyCookieName = $keyCookieName;
        $this->_valueCookieName = $valueCookieName;
        $this->_cipher = $cipher;
        $this->_keyLifetime = ($keyLifetime !== null) ? 
            $keyLifetime : (int) ini_get('session.gc_maxlifetime');

        // Retrieve public key
        if (!empty($_COOKIE[$this->_keyCookieName])) {
            try {
                $this->_publicKey = base64_decode(
                    $_COOKIE[$this->_keyCookieName]
                );
            } catch (Exception $exception) {
                $this->_publicKey = null;
                require_once 'Zend/Auth/Storage/Exception.php';
                throw new Zend_Auth_Storage_Exception($exception);
            }
        }
        
        // Retrieve data
        if (!empty($_COOKIE[$this->_valueCookieName])) {
            try {
                $rawCookie = $this->_decrypt(
                    $_COOKIE[$this->_valueCookieName]
                );
                // lifetime reached?
                if (time() < $rawCookie[0]) {
                    // no, accept data
                    $this->_cookie = $rawCookie[1];
                } else {
                    // yes, invalidate public key
                    $this->_publicKey = null;
                }
            } catch (Exception $exception) {
                $this->_cookie = null;
                $this->_publicKey = null;
                require_once 'Zend/Auth/Storage/Exception.php';
                throw new Zend_Auth_Storage_Exception($exception);
            }
        } else {
            $this->_publicKey = null;
        }
        
        // Setup public key
        if (empty($this->_publicKey)) {
            $this->_publicKey = mcrypt_create_iv(
                mcrypt_get_iv_size($this->_cipher, MCRYPT_MODE_CBC),
                MCRYPT_RAND
            );
            $_COOKIE[$this->_keyCookieName] = base64_encode($this->_publicKey);
            setcookie(
                $this->_keyCookieName,
                base64_encode($this->_publicKey),
                0,
                '/',
                '',
                false,
                true
            );
        }
        
        // refresh lifetime
        $this->write($this->_cookie);
    }
    /**
     * Encrypt the string
     *
     * @param string $string
     * @return string
     */
    protected function _encrypt($string)
    {
        $string = serialize($string);
        $blockSize = mcrypt_get_block_size($this->_cipher, MCRYPT_MODE_CBC);
        $pad = $blockSize - (strlen($string) % $blockSize);
        $string .= str_repeat(chr($pad), $pad);
        $result = mcrypt_encrypt(
            $this->_cipher,
            $this->_secretKey,
            $string,
            MCRYPT_MODE_CBC,
            $this->_publicKey
        );
        return base64_encode(gzcompress($result, 6));
    }
    /**
     * Decrypt the string
     *
     * @param string $string
     * @return string
     */
    protected function _decrypt($string)
    {
        $result = mcrypt_decrypt(
            $this->_cipher,
            $this->_secretKey,
            gzuncompress(base64_decode($string)),
            MCRYPT_MODE_CBC,
            $this->_publicKey
        );
        $pad = ord($result[strlen($result) - 1]);
        $result = substr($result, 0, strlen($result) - $pad);
        return unserialize($result);
    }
    /**
     * Defined by Zend_Auth_Storage_Interface
     *
     * @return boolean
     */
    public function isEmpty()
    {
        return empty($this->_cookie);
    }
    /**
     * Defined by Zend_Auth_Storage_Interface
     *
     * @return mixed
     */
    public function read()
    {
        return $this->_cookie;
    }
    /**
     * Defined by Zend_Auth_Storage_Interface
     *
     * @param  mixed $contents
     * @return void
     */
    public function write($contents)
    {
        try {
            $encryptedContents = $this->_encrypt(
                array(time() + $this->_keyLifetime, $contents)
            );
        } catch (Exception $exception) {
            $encryptedContents = $contents = null;
            require_once 'Zend/Auth/Storage/Exception.php';
            throw new Zend_Auth_Storage_Exception($exception);
        }
        $this->_cookie = $contents;
        $_COOKIE[$this->_valueCookieName] = $encryptedContents;
        setcookie(
            $this->_valueCookieName,
            $encryptedContents,
            0,
            '/',
            '',
            false,
            true
        );
    }
    /**
     * Defined by Zend_Auth_Storage_Interface
     *
     * @return void
     */
    public function clear()
    {
        $this->_cookie = null;
        unset($_COOKIE[$this->_valueCookieName]);
        setcookie($this->_valueCookieName, '', 1, '/', '', false, true);
    }
}
