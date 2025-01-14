package cn.hs.auth.utils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * @author huangshen
 * @version 1.0
 * @date 2025/1/14 16:49
 */
public class KeyPairGeneratorUtils {
    /**
     * 生成一个 RSA 密钥对
     *
     * @return KeyPair 密钥对
     * @throws NoSuchAlgorithmException 如果没有找到算法
     */
    public static KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        // 使用 RSA 算法生成密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        // 设置密钥的大小
        keyPairGenerator.initialize(2048); // 2048 是常见的密钥长度

        // 生成并返回密钥对
        return keyPairGenerator.generateKeyPair();
    }
}
