<?php

declare(strict_types=1);

namespace Platine\Security;

$mock_md5_to_value = false;
$mock_base64_encode_to_value = false;
$mock_base64_decode_to_value = false;

function md5(string $string)
{
    global $mock_md5_to_value;

    if ($mock_md5_to_value) {
        return '123456abcdfe';
    }

    return \md5($string);
}

function base64_encode(string $string)
{
    global $mock_base64_encode_to_value;

    if ($mock_base64_encode_to_value) {
        return 'my_base64_encode';
    }

    return \base64_encode($string);
}

function base64_decode(string $string)
{
    global $mock_base64_decode_to_value;

    if ($mock_base64_decode_to_value) {
        return 'my_base64_decode';
    }

    return \base64_decode($string);
}

namespace Platine\Security\Encryption;

$mock_extension_loaded_to_false = false;
$mock_extension_loaded_to_true = false;
$mock_openssl_get_cipher_methods_to_array = false;
$mock_openssl_random_pseudo_bytes_to_false = false;
$mock_openssl_random_pseudo_bytes_to_value = false;
$mock_openssl_decrypt_to_false = false;
$mock_openssl_decrypt_to_value = false;
$mock_openssl_encrypt_to_value = false;
$mock_openssl_encrypt_to_false = false;
$mock_openssl_cipher_iv_length_to_false = false;
$mock_openssl_cipher_iv_length_to_value = false;
$mock_sha1_to_value = false;
$mock_chr_to_value = false;
$mock_ord_to_value = false;

function chr(int $string)
{
    global $mock_chr_to_value;

    if ($mock_chr_to_value) {
        return $string > 10 ? 'a' : 'z';
    }

    return \chr($string);
}

function ord(string $string)
{
    global $mock_ord_to_value;

    if ($mock_ord_to_value) {
        return $string > 'a' ? 10 : 5 ;
    }

    return \ord($string);
}

function sha1(string $string)
{
    global $mock_sha1_to_value;

    if ($mock_sha1_to_value) {
        return '123456abcdfe';
    }

    return \sha1($string);
}

function extension_loaded(string $string)
{
    global $mock_extension_loaded_to_false,
            $mock_extension_loaded_to_true;

    if ($mock_extension_loaded_to_true) {
        return true;
    } elseif ($mock_extension_loaded_to_false) {
        return false;
    }

    return \extension_loaded($string);
}

function openssl_get_cipher_methods()
{
    global $mock_openssl_get_cipher_methods_to_array;

    if ($mock_openssl_get_cipher_methods_to_array) {
        return ['AES-256-CBC', 'foo_cipher'];
    }

    return \openssl_get_cipher_methods();
}

function openssl_random_pseudo_bytes(int $length)
{
    global $mock_openssl_random_pseudo_bytes_to_false,
            $mock_openssl_random_pseudo_bytes_to_value;

    if ($mock_openssl_random_pseudo_bytes_to_value) {
        return 'abcd';
    } elseif ($mock_openssl_random_pseudo_bytes_to_false) {
        return false;
    }

    return \openssl_random_pseudo_bytes($length);
}

function openssl_decrypt(string $data, string $method, string $key, int $options = 0, string $iv = "")
{
    global $mock_openssl_decrypt_to_false,
            $mock_openssl_decrypt_to_value;

    if ($mock_openssl_decrypt_to_value) {
        return 'decripted';
    } elseif ($mock_openssl_decrypt_to_false) {
        return false;
    }

    return \openssl_decrypt($data, $method, $key, $options, $iv);
}

function openssl_encrypt(string $data, string $method, string $key, int $options = 0, string $iv = "")
{
    global $mock_openssl_encrypt_to_false,
            $mock_openssl_encrypt_to_value;

    if ($mock_openssl_encrypt_to_value) {
        return 'encripted';
    } elseif ($mock_openssl_encrypt_to_false) {
        return false;
    }

    return \openssl_encrypt($data, $method, $key, $options, $iv);
}


function openssl_cipher_iv_length(string $method)
{
     global $mock_openssl_cipher_iv_length_to_false,
            $mock_openssl_cipher_iv_length_to_value;

    if ($mock_openssl_cipher_iv_length_to_value) {
        return 20;
    } elseif ($mock_openssl_cipher_iv_length_to_false) {
        return false;
    }

    return \openssl_cipher_iv_length($method);
}

namespace Platine\Security\Hash;

$mock_password_hash_to_false = false;
$mock_password_hash_to_value = false;

$mock_password_verify_to_false = false;
$mock_password_verify_to_true = false;

function password_hash(string $password, $algo, array $options = [])
{
     global $mock_password_hash_to_false,
            $mock_password_hash_to_value;

    if ($mock_password_hash_to_value) {
        return 'my_hash';
    } elseif ($mock_password_hash_to_false) {
        return false;
    }

    return \password_hash($password, $algo, $options);
}

function password_verify(string $password, string $hash)
{
     global $mock_password_verify_to_false,
            $mock_password_verify_to_true;

    if ($mock_password_verify_to_true) {
        return true;
    } elseif ($mock_password_verify_to_false) {
        return false;
    }

    return \password_verify($password, $hash);
}
