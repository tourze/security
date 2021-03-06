<?php

namespace tourze\Security\Password\Hash;

use tourze\Security\Password\Hash;
use tourze\Security\Password\HashInterface;

/**
 * 最简单的MD5格式
 *
 * @package tourze\Security\Password\Hash
 */
class MD5 extends Hash implements HashInterface
{

    /**
     * {@inheritdoc}
     */
    public function hash()
    {
        return (string) md5($this->text);
    }
}
