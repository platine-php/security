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
 *  @file HashInterface.php
 *
 *  The hash interface
 *
 *  @package    Platine\Security\Hash
 *  @author Platine Developers Team
 *  @copyright  Copyright (c) 2020
 *  @license    http://opensource.org/licenses/MIT  MIT License
 *  @link   https://www.platine-php.com
 *  @version 1.0.0
 *  @filesource
 */

declare(strict_types=1);

namespace Platine\Security\Hash;

/**
 * Class HashInterface
 * @package Platine\Security\Hash
 */
interface HashInterface
{
    /**
     * Hash the given string
     * @param string $plain
     * @return string the hashed value
     */
    public function hash(string $plain): string;

    /**
     * Verify the plain and hashed
     * @return bool
     */
    public function verify(string $plain, string $hashed): bool;
}
