<?php
require_once 'Zend/Auth.php';
require_once 'Zend/Auth/Adapter/Digest.php';
require_once dirname(__FILE__) . '/../Cookie.php';

// map IP to the secret key in order to prevent cookie hijack
$secret = md5(md5('My secret key') . md5($_SERVER['REMOTE_ADDR']));
// set up cookie storage
$auth = Zend_Auth::getInstance()->setStorage(
    new Auth_Storage_Cookie($secret, 'k', 'v', MCRYPT_RIJNDAEL_256)
);

// Logged in?
if ($auth->hasIdentity()) {
    $username = $auth->getStorage()->read();
    Zend_Auth::getInstance()->clearIdentity();
    echo "I remember you, {$username}!.. Goodbye!.. Please reload the page";
    exit;
}

// Do login
$username = 'someUser';
$password = 'somePassword';
$realm = 'Some Realm';
$filename = 'digest.txt';

$adapter = new Zend_Auth_Adapter_Digest(
    $filename,
    $realm,
    $username,
    $password
);
$result = $auth->authenticate($adapter);
if ($result->isValid()) {
    $auth->getStorage()->write($username);
    echo "Welcome, {$username}!.. Please reload the page";
}

