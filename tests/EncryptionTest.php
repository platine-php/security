<?php

declare(strict_types=1);

namespace Platine\Test\Security;

use Platine\PlatineTestCase;
use Platine\Security\Encryption;
use Platine\Security\Encryption\AdapterInterface;
use Platine\Security\Encryption\OpenSSL;
use Platine\Security\Exception\EncryptionException;

/**
 * Encryption class tests
 *
 * @group core
 * @group security
 */
class EncryptionTest extends PlatineTestCase
{

    public function testConstructor(): void
    {
        $adapter = $this->getMockInstance(OpenSSL::class);
        $s = new Encryption($adapter);
        $this->assertInstanceOf(Encryption::class, $s);
        $this->assertInstanceOf(AdapterInterface::class, $s->getAdapter());
        $this->assertEquals($s->getAdapter(), $adapter);
    }

    public function testSetSecret(): void
    {
        global $mock_md5_to_value;

        $mock_md5_to_value = true;

        $adapter = $this->getMockInstance(OpenSSL::class);
        $s = new Encryption($adapter);
        $s->setSecret('my secret');
        $this->assertEquals('my secret', $this->getPropertyValue(Encryption::class, $s, 'secret'));
        $this->assertEquals('123456abcdfe', $this->getPropertyValue(Encryption::class, $s, 'hashedSecret'));
    }

    public function testEncode(): void
    {
        global $mock_base64_encode_to_value;

        $mock_base64_encode_to_value = true;

        $adapter = $this->getMockInstance(OpenSSL::class);
        $s = new Encryption($adapter);
        $res = $s->encode('my data');
        $this->assertEquals('my_base64_encode', $res);
    }

    public function testDecode(): void
    {
        global $mock_base64_decode_to_value;

        $mock_base64_decode_to_value = true;

        $adapter = $this->getMockInstance(OpenSSL::class, ['decrypt' => 'my_decripted_data']);
        $s = new Encryption($adapter);
        $res = $s->decode('my encoded data');
        $this->assertEquals('my_decripted_data', $res);
    }

    public function testDecodeInvalid(): void
    {
        global $mock_base64_decode_to_value;

        $mock_base64_decode_to_value = true;

        $adapter = $this->getMockInstance(OpenSSL::class, ['getIVSize' => 100]);
        $s = new Encryption($adapter);

        $this->expectException(EncryptionException::class);
        $s->decode('my');
    }
}
