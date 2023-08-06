package com.aspire.zxws.cas;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.MessageDigest;

/**
 * @Author 曹春
 * @PackageName: com.aspire.zxws.cas
 * @ClassName CustomPasswordEncoder
 * @Description: TODO
 * @Date: 2023/8/6 8:33
 * Copyright (c) 2023 卓望公司版权所有
 */
public class CustomPasswordEncoder implements PasswordEncoder {
    @Override
    public String encode(CharSequence password) {
        try {
            // 给数据进行SHA-256加密
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(password.toString().getBytes("UTF-8"));
            String encodePassword = new String(Base64.encodeBase64(digest));
            System.out.println("encode方法：加密前（" + password + "），加密后（" + encodePassword + "）");
            return encodePassword;
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodePassword) {
        // 判断密码是否存在
        if (rawPassword == null) {
            return false;
        }
        // 通过SHA-256加密后的密码
        String pass = this.encode(rawPassword.toString());

        System.out.println(
                "matches方法：rawPassword：" + rawPassword + "，encodePassword：" + encodePassword + "，pass：" + pass);

        // 比较密码是否相等的问题
        return pass.equals(encodePassword);
    }
}
