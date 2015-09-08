<?php

namespace tourze\Security\Password\Hash;

use tourze\Security\Password\Hash;
use tourze\Security\Password\HashInterface;

/**
 * 不加密
 *
 * @package tourze\Security\Password\Hash
 */
class Plain extends Hash implements HashInterface
{

    /**
     * {@inheritdoc}
     */
    public function hash()
    {
        return trim($this->text);
    }
}
