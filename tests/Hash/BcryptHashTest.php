<?php

declare(strict_types=1);

namespace Platine\Test\Security\Hash;

use Platine\PlatineTestCase;
use Platine\Security\Exception\HashException;
use Platine\Security\Hash\BcryptHash;

/**
 * BcryptHash class tests
 *
 * @group core
 * @group security
 */
class BcryptHashTest extends PlatineTestCase
{

    public function testHashSuccess(): void
    {
        global $mock_password_hash_to_value;
        $mock_password_hash_to_value = true;
        $s = new BcryptHash();

        $this->assertEquals($s->hash('my plain text'), 'my_hash');
    }

    public function testHashFailed(): void
    {
        global $mock_password_hash_to_false;
        $mock_password_hash_to_false = true;
        $s = new BcryptHash();
        $this->expectException(HashException::class);
        $s->hash('my plain text');
    }

    public function testVerifySuccess(): void
    {
        global $mock_password_verify_to_true;
        $mock_password_verify_to_true = true;
        $s = new BcryptHash();

        $this->assertTrue($s->verify('my plain text', 'my hash text'));
    }

    public function testVerifyFailed(): void
    {
        global $mock_password_verify_to_false;
        $mock_password_verify_to_false = true;
        $s = new BcryptHash();
        $this->assertFalse($s->verify('my plain text', 'my hash text'));
    }
}
