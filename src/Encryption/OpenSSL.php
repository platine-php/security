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
 *  @file OpenSSL.php
 *
 *  The OpenSSL adapter class
 *
 *  @package    Platine\Security\Encryption
 *  @author Platine Developers Team
 *  @copyright  Copyright (c) 2020
 *  @license    http://opensource.org/licenses/MIT  MIT License
 *  @link   https://www.platine-php.com
 *  @version 1.0.0
 *  @filesource
 */

declare(strict_types=1);

namespace Platine\Security\Encryption;

use Platine\Security\Exception\EncryptionException;
use RuntimeException;

/**
 * Class OpenSSL
 * @package Platine\Security\Encryption
 */
class OpenSSL implements AdapterInterface
{
    /**
     * OpenSSL cipher method constant
     * @var string
     */
    protected string $cipher = 'AES-256-CBC';

    /**
     * OpenSSL input/output option constant
     * @var int
     */
    protected int $option = OPENSSL_RAW_DATA;


    /**
     * Create new instance
     * @param array<string, mixed> $config
     */
    public function __construct(array $config = [])
    {
        if (!extension_loaded('openssl')) {
            throw new RuntimeException(
                'OpenSSL extension is not loaded or actived, '
                   . 'please check your PHP configuration'
            );
        }

        if (isset($config['cipher']) && is_string($config['cipher'])) {
            $cipher = $config['cipher'];
            if (!in_array($cipher, openssl_get_cipher_methods())) {
                throw new EncryptionException(sprintf(
                    'Invalid OpenSSL cipher [%s]',
                    $cipher
                ));
            } else {
                $this->cipher = $cipher;
            }
        }

        if (isset($config['option']) && is_int($config['option'])) {
            $option = $config['option'];
            $options = [
                OPENSSL_RAW_DATA,
                OPENSSL_ZERO_PADDING
            ];

            if (!in_array($option, $options)) {
                throw new EncryptionException(sprintf(
                    'Invalid OpenSSL option [%d] must be one of [%s]',
                    $option,
                    implode(', ', $options)
                ));
            } else {
                $this->option = $option;
            }
        }
    }

    /**
     * {@inhereitdoc}
     */
    public function createIV(int $size): string
    {
        $bytes = openssl_random_pseudo_bytes($size);
        if ($bytes === false) {
            throw new EncryptionException(
                'Error occured when creating initialization vector'
            );
        }

        return $bytes;
    }

    /**
     * {@inhereitdoc}
     */
    public function decrypt(string $key, string $data, string $initVector): string
    {
        $decrypted = openssl_decrypt(
            $data,
            $this->cipher,
            $key,
            $this->option,
            $initVector
        );

        if ($decrypted === false) {
            throw new EncryptionException(
                'Error occured when decrypting the data'
            );
        }

        return $decrypted;
    }

    /**
     * {@inhereitdoc}
     */
    public function encrypt(
        string $key,
        string $data,
        string $initVector
    ): string {
        $encrypted = openssl_encrypt(
            $data,
            $this->cipher,
            $key,
            $this->option,
            $initVector
        );

        if ($encrypted === false) {
            throw new EncryptionException(
                'Error occured when encrypting the data'
            );
        }

        return $encrypted;
    }

    /**
     * {@inhereitdoc}
     */
    public function getIVSize(): int
    {
        $size = openssl_cipher_iv_length($this->cipher);

        if ($size === false) {
            throw new EncryptionException(
                'Error occured when get the initialization vector size'
            );
        }

        return $size;
    }
}
