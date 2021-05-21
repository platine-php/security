<?php

declare(strict_types=1);

namespace Platine\Test\Security;

use Platine\PlatineTestCase;
use Platine\Security\Encryption;
use Platine\Security\Encryption\AdapterInterface;
use Platine\Security\Encryption\OpenSSL;

/**
 * Encryption class tests
 *
 * @group core
 * @group Security
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
}
