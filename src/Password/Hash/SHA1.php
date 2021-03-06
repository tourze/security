<?php

namespace tourze\Security\Password\Hash;

use tourze\Security\Password\Hash;
use tourze\Security\Password\HashInterface;

/**
 * 最简单的SHA1格式
 *
 * @package tourze\Security\Password\Hash
 */
class SHA1 extends Hash implements HashInterface
{

    /**
     * {@inheritdoc}
     */
    public function hash()
    {
        return (string) sha1($this->text);
    }
}
