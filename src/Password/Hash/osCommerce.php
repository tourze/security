<?php

namespace tourze\Security\Password\Hash;

use tourze\Security\Password\Hash;
use tourze\Security\Password\HashInterface;

/**
 * osCommerce加密方式
 *
 * @package tourze\Security\Password\Hash
 */
class osCommerce extends Hash implements HashInterface
{

    /**
     * @var string
     */
    public $salt = '';

    /**
     * {@inheritdoc}
     */
    public function hash()
    {
        return (string) md5($this->salt . $this->text);
    }
}
