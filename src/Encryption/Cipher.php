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
 *  @file Cipher.php
 *
 *  The Cipher helper class
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

/**
 * @class Cipher
 * @package Platine\Security\Encryption
 */
class Cipher
{
    /**
     * The data to use for encryption/decryption
     * @var string
     */
    protected string $data;

    /**
     * The secret key
     * @var string
     */
    protected string $key;

    /**
     * The noised message
     * @var string
     */
    protected string $message = '';

    /**
     * Create new instance
     * @param string $data
     * @param string $key
     */
    public function __construct(string $data, string $key)
    {
        $this->data = $data;
        $this->key = sha1($key);
    }

    /**
     * Adds permuted noise to the IV + encrypted data to protect
     * against Man-in-the-middle attacks on CBC mode ciphers
     * @return string
     */
    public function addCipherNoise(): string
    {
        $dataLength = strlen($this->data);
        $keyLength = strlen($this->key);

        for (
            $i = 0, $j = 0, $ld = $dataLength, $lk = $keyLength;
            $i < $ld;
            ++$i, ++$j
        ) {
            if ($j >= $lk) {
                $j = 0;
            }

            $this->message .= chr((ord($this->data[$i]) + ord($this->key[$j])) % 256);
        }

        return $this->message;
    }

    /**
     * Removes permuted noise from the IV + encrypted data
     * @return string
     */
    public function removeCipherNoise(): string
    {
        $dataLength = strlen($this->data);
        $keyLength = strlen($this->key);

        for (
            $i = 0, $j = 0, $ld = $dataLength, $lk = $keyLength;
            $i < $ld;
            ++$i, ++$j
        ) {
            if ($j >= $lk) {
                $j = 0;
            }

            $temp = ord($this->data[$i]) - ord($this->key[$j]);

            if ($temp < 0) {
                $temp += 256;
            }
            $this->message .= chr($temp);
        }

        return $this->message;
    }
}
