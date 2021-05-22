<?php

declare(strict_types=1);

namespace Platine\Test\Security\Encryption;

use Platine\PlatineTestCase;
use Platine\Security\Encryption\OpenSSL;
use Platine\Security\Exception\EncryptionException;
use RuntimeException;

/**
 * OpenSSL class tests
 *
 * @group core
 * @group security
 */
class OpenSSLTest extends PlatineTestCase
{

    public function testConstructorExtensionNotLoaded(): void
    {
        global $mock_extension_loaded_to_false;
        $mock_extension_loaded_to_false = true;
        $this->expectException(RuntimeException::class);

        $s = new OpenSSL([]);
    }

    public function testConstructorValidCipher(): void
    {
        global $mock_extension_loaded_to_true,
                $mock_openssl_get_cipher_methods_to_array;


        $mock_extension_loaded_to_true = true;
        $mock_openssl_get_cipher_methods_to_array = true;

        $s = new OpenSSL([
            'cipher' => 'foo_cipher'
        ]);

        $this->assertEquals('foo_cipher', $this->getPropertyValue(OpenSSL::class, $s, 'cipher'));
    }

    public function testConstructorInvalidCipher(): void
    {
        global $mock_extension_loaded_to_true,
                $mock_openssl_get_cipher_methods_to_array;


        $mock_extension_loaded_to_true = true;
        $mock_openssl_get_cipher_methods_to_array = true;

        $this->expectException(EncryptionException::class);
        $s = new OpenSSL([
            'cipher' => 'invalid_cipher'
        ]);
    }

    public function testConstructorInvalidOption(): void
    {
        global $mock_extension_loaded_to_true;

        $mock_extension_loaded_to_true = true;

        $this->expectException(EncryptionException::class);
        $s = new OpenSSL([
            'option' => 12345
        ]);
    }

    public function testConstructorValidOption(): void
    {
        global $mock_extension_loaded_to_true;

        $mock_extension_loaded_to_true = true;

        $s = new OpenSSL([
            'option' => 1
        ]);

        $this->assertEquals(1, $this->getPropertyValue(OpenSSL::class, $s, 'option'));
    }

    public function testCreateIVFailed(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_random_pseudo_bytes_to_false;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_random_pseudo_bytes_to_false = true;

        $s = new OpenSSL();

        $this->expectException(EncryptionException::class);
        $s->createIV(12);
    }

    public function testCreateIVSuccess(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_random_pseudo_bytes_to_value;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_random_pseudo_bytes_to_value = true;

        $s = new OpenSSL();

        $res = $s->createIV(12);

        $this->assertEquals('abcd', $res);
    }

    public function testDecryptFailed(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_decrypt_to_false;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_decrypt_to_false = true;

        $s = new OpenSSL();

        $this->expectException(EncryptionException::class);
        $s->decrypt('key', 'my data', 'my iv');
    }

    public function testDecryptSuccess(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_decrypt_to_value;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_decrypt_to_value = true;

        $s = new OpenSSL();

        $res = $s->decrypt('key', 'my data', 'my iv');

        $this->assertEquals('decripted', $res);
    }

    public function testEncryptFailed(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_encrypt_to_false;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_encrypt_to_false = true;

        $s = new OpenSSL();

        $this->expectException(EncryptionException::class);
        $s->encrypt('key', 'my data', 'my iv');
    }

    public function testEncryptSuccess(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_encrypt_to_value;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_encrypt_to_value = true;

        $s = new OpenSSL();

        $res = $s->encrypt('key', 'my data', 'my iv');

        $this->assertEquals('encripted', $res);
    }

    public function testGetIVSizeFailed(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_cipher_iv_length_to_false;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_cipher_iv_length_to_false = true;

        $s = new OpenSSL();

        $this->expectException(EncryptionException::class);
        $s->getIVSize();
    }

    public function testGetIVSizeSuccess(): void
    {
        global $mock_extension_loaded_to_true,
               $mock_openssl_cipher_iv_length_to_value;

        $mock_extension_loaded_to_true = true;
        $mock_openssl_cipher_iv_length_to_value = true;

        $s = new OpenSSL();

        $res = $s->getIVSize();

        $this->assertEquals(20, $res);
    }
}
