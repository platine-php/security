<?php

declare(strict_types=1);

namespace Platine\Test\Security\Encryption;

use Platine\PlatineTestCase;
use Platine\Security\Encryption\Cipher;
use Platine\Security\Encryption\OpenSSL;

/**
 * Cipher class tests
 *
 * @group core
 * @group security
 */
class CipherTest extends PlatineTestCase
{

    public function testConstructorExtensionNotLoaded(): void
    {
        global $mock_sha1_to_value;

        $mock_sha1_to_value = true;

        $s = new Cipher('my data', 'my key');

        $this->assertEquals('my data', $this->getPropertyValue(Cipher::class, $s, 'data'));
        $this->assertEquals('123456abcdfe', $this->getPropertyValue(Cipher::class, $s, 'key'));
    }

    public function testAddCipherNoise(): void
    {
        global $mock_sha1_to_value,
               $mock_chr_to_value,
                $mock_ord_to_value;

        $mock_sha1_to_value = true;
        $mock_chr_to_value = true;
        $mock_ord_to_value = true;

        $s = new Cipher('my data that will be add noise', 'my key');

        $res = $s->addCipherNoise();
        $this->assertEquals($res, 'aazazazaaaaazaaaazaaaaaazaaaaa');
    }

    public function testRemoveCipherNoise(): void
    {
        global $mock_sha1_to_value,
               $mock_chr_to_value,
                $mock_ord_to_value;

        $mock_sha1_to_value = true;
        $mock_chr_to_value = true;
        $mock_ord_to_value = true;

        $s = new Cipher('aazazazaaaaazaaaazaaaaaazaaaaa', 'my key');

        $res = $s->removeCipherNoise();
        $this->assertEquals($res, 'zzzzzzzaaaaazzzzzzzaaaaazzzzzz');
    }
}
