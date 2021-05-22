<?php

/**
 * Platine Security
 *
 * Platine Security provides a complete security system with encryption, hash support
 *
 * This content is released under the MIT License (MIT)
 *
 * Copyright (c) 2020 Platine Security
 * Copyright (c) 2013 G4Code
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 *  @file Lang.php
 *
 *  The translator main class
 *
 *  @package    Platine\Security
 *  @author Platine Developers Team
 *  @copyright  Copyright (c) 2020
 *  @license    http://opensource.org/licenses/MIT  MIT License
 *  @link   http://www.iacademy.cf
 *  @version 1.0.0
 *  @filesource
 */

declare(strict_types=1);

namespace Platine\Security;

use Platine\Security\Encryption\AdapterInterface;
use Platine\Security\Encryption\Cipher;
use Platine\Security\Encryption\OpenSSL;
use Platine\Security\Exception\EncryptionException;

/**
 * Class Lang
 * @package Platine\Security
 */
class Encryption
{

    /**
     * The adapter instance
     * @var AdapterInterface
     */
    protected AdapterInterface $adapter;

    /**
     * The encryption/decryption secret key
     * @var string
     */
    protected string $secret;

    /**
     * The hashed secret
     * @var string
     */
    protected string $hashedSecret;

    /**
     * The initialization vector
     * @var int
     */
    protected int $initVectorSize;

    /**
     * Create new instance
     * @param AdapterInterface|null $adapter
     */
    public function __construct(AdapterInterface $adapter = null)
    {
        $this->adapter = $adapter ? $adapter : new OpenSSL([]);
        $this->initVectorSize = $this->adapter->getIVSize();
        $this->setSecret('');
    }

    /**
     * Return the adapter instance
     * @return AdapterInterface
     */
    public function getAdapter(): AdapterInterface
    {
        return $this->adapter;
    }

    /**
     * Set secret
     * @param string $secret
     * @return $this
     */
    public function setSecret(string $secret): self
    {
        $this->secret = $secret;
        $this->hashedSecret = md5($secret);

        return $this;
    }

    /**
     * Encode the given data
     * @param string $data
     * @return string
     */
    public function encode(string $data): string
    {
        return $this->encryptData($data);
    }

    /**
     * Decode the given encrypted data
     * @param string $data
     * @return string
     */
    public function decode(string $data): string
    {
        return $this->decryptData($data);
    }


    /**
     * Encrypt the data
     * @param string $data
     * @return string
     */
    protected function encryptData(string $data): string
    {
        $initVector = $this->adapter->createIV($this->initVectorSize);
        $encrypted = $initVector . $this->adapter->encrypt(
            $this->hashedSecret,
            $data,
            $initVector
        );

        $cipher = new Cipher($encrypted, $this->hashedSecret);

        return $this->base64UrlEncode(
            $cipher->addCipherNoise()
        );
    }

    /**
     * Decrypt the encrypted data
     * @param string $data
     * @return string
     */
    protected function decryptData(string $data): string
    {
        $encrypted = $this->base64UrlDecode($data);

        $cipher = new Cipher($encrypted, $this->hashedSecret);

        $cleanEncrypted = $cipher->removeCipherNoise();

        if ($this->initVectorSize > strlen($cleanEncrypted)) {
            throw new EncryptionException('The encrypted data to decode is invalid');
        }

        $initVector = substr($cleanEncrypted, 0, $this->initVectorSize);

        $dataEncrypted = substr($cleanEncrypted, $this->initVectorSize);

        return rtrim(
            $this->adapter->decrypt(
                $this->hashedSecret,
                $dataEncrypted,
                $initVector
            ),
            "\0"
        );
    }

    /**
     * Base64 URL encode
     * @param string $value
     * @return string
     */
    protected function base64UrlEncode(string $value): string
    {
        return rtrim(
            strtr(
                base64_encode($value),
                '+/',
                '-_'
            ),
            '='
        );
    }

    /**
     * Base64 URL decode
     * @param string $value
     * @return string
     */
    protected function base64UrlDecode(string $value): string
    {
        return base64_decode(str_pad(
            strtr($value, '-_', '+/'),
            strlen($value) % 4,
            '=',
            STR_PAD_RIGHT
        ));
    }
}
