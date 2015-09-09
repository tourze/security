<?php

namespace tourze\Security;

use Rhumsaa\Uuid\Uuid as VendorUUID;
use Rhumsaa\Uuid\Exception\UnsatisfiedDependencyException;
use tourze\Security\Exception\UnsupportedMethodException;

/**
 * UUID生成器
 *
 * @package tourze\Security
 */
class UUID
{
    /**
     * UUID1，基于时间戳
     *
     * @param int|string $node
     * @param int        $clockSeq
     * @return string
     */
    public static function v1($node = null, $clockSeq = null)
    {
        try
        {
            $uuid1 = VendorUUID::uuid1($node, $clockSeq);
            return $uuid1->toString();
        }
        catch (UnsatisfiedDependencyException $e)
        {
            return false;
        }
    }

    /**
     * @throws \tourze\Security\Exception\UnsupportedMethodException
     */
    public static function v2()
    {
        throw new UnsupportedMethodException('The UUID2 is not supported.');
    }

    /**
     * 基于名字的MD5散列值
     * [!!] 同一命名空间的同一名字会生成相同的uuid
     *
     * @param  VendorUUID|string $namespace
     * @param  string            $name
     * @return string
     */
    public static function v3($namespace = VendorUUID::NAMESPACE_DNS, $name = 'php.net')
    {
        try
        {
            $uuid3 = VendorUUID::uuid3($namespace, $name);
            return $uuid3->toString();
        }
        catch (UnsatisfiedDependencyException $e)
        {
            return false;
        }
    }

    /**
     * 基于随机数生成的UUID
     *
     * @return string
     */
    public static function v4()
    {
        try
        {
            $uuid4 = VendorUUID::uuid4();
            return $uuid4->toString();
        }
        catch (UnsatisfiedDependencyException $e)
        {
            return false;
        }
    }

    /**
     * 基于名字的SHA-1散列值，与v3一样，区别是使用哈希算法换了sha1
     *
     * @param  string $namespace
     * @param  string $name
     * @return string
     */
    public static function v5($namespace = VendorUUID::NAMESPACE_DNS, $name = 'php.net')
    {
        try
        {
            $uuid5 = VendorUUID::uuid5($namespace, $name);
            return $uuid5->toString();
        }
        catch (UnsatisfiedDependencyException $e)
        {
            return false;
        }
    }

}
