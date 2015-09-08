<?php

namespace tourze\Security;

use tourze\Base\Helper\Arr;
use tourze\Security\Password\HashInterface;
use tourze\Security\Password\Hash\Joomla;
use tourze\Security\Password\Hash\MD5;
use tourze\Security\Password\Hash\MD5Twice;
use tourze\Security\Password\Hash\osCommerce;
use tourze\Security\Password\Hash\Plain;
use tourze\Security\Password\Hash\SHA1;
use ZxcvbnPhp\Zxcvbn;

/**
 * 密码相关的安全方法
 *
 * @package tourze\Security
 */
class Password
{

    /**
     * 默认密码加密方式，最简单的MD5
     */
    const MD5_HASH = 'md5';

    /**
     * 简单的sha1加密
     */
    const SHA1_HASH = 'sha1';

    /**
     * 双重md5
     */
    const MD5_TWICE_HASH = 'md5_md5';

    /**
     * 双重sha1
     */
    const SHA1_TWICE_HASH = 'sha1_sha1';

    /**
     * md5($text.$salt)，Joomla采用这个方式
     */
    const PASS_SALT_MD5_HASH = 'pass_salt_md5';

    /**
     * md5($salt.$text)，osCommerce的加密方式
     */
    const SALT_PASS_MD5_HASH = 'salt_pass_md5';

    /**
     * 检测输入密码的强壮程度，并返回检测结果，结果越大，密码就越健壮
     *
     * @param $password
     * @return int
     */
    public static function strength($password)
    {
        $zxcvbn = new Zxcvbn();
        $result = $zxcvbn->passwordStrength($password);

        return (int) Arr::get($result, 'score');
    }

    /**
     * @param string $text     明文
     * @param string $hashType 加密方式
     * @param array  $extra    附加参数
     * @return string
     */
    public static function hash($text, $hashType = self::MD5_HASH, array $extra = null)
    {
        $params = Arr::merge(['text' => $text], (array) $extra);
        switch ($hashType)
        {
            case self::MD5_HASH:
                $object = new MD5($params);
                break;
            case self::SHA1_HASH:
                $object = new SHA1($params);
                break;
            case self::MD5_TWICE_HASH:
                $object = new MD5Twice($params);
                break;
            case self::PASS_SALT_MD5_HASH:
                $object = new Joomla($params);
                break;
            case self::SALT_PASS_MD5_HASH:
                $object = new osCommerce($params);
                break;
            default:
                $object = new Plain($params);
        }

        /** @var HashInterface $object */
        return (string) $object->hash();
    }

    /**
     * 单次MD5
     *
     * @param string $str
     * @return string
     */
    public static function md5($str)
    {
        return self::hash($str, self::MD5_HASH);
    }

    /**
     * 两次MD5
     *
     * @param string $str
     * @return string
     */
    public static function md5Twice($str)
    {
        return self::hash($str, self::MD5_TWICE_HASH);
    }

    /**
     * SHA1
     *
     * @param string $str
     * @return string
     */
    public static function sha1($str)
    {
        return self::hash($str, self::SHA1_HASH);
    }

    /**
     * md5+salt加密
     *
     * @param string $str
     * @param string $salt
     * @return string
     */
    public static function md5Salt($str, $salt)
    {
        return self::hash($str, self::PASS_SALT_MD5_HASH, [
            'salt' => $salt,
        ]);
    }

    /**
     * salt+md5
     *
     * @param string $str
     * @param string $salt
     * @return string
     */
    public static function saltMd5($str, $salt)
    {
        return self::hash($str, self::SALT_PASS_MD5_HASH, [
            'salt' => $salt,
        ]);
    }
}
