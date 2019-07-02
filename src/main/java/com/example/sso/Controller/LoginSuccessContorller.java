package com.example.sso.Controller;

import com.example.sso.util.CookieUtil;
import com.example.sso.util.EncryptUtil;
import org.springframework.stereotype.Controller;
import org.springframework.util.DigestUtils;
import org.springframework.web.HttpRequestHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Controller
@RequestMapping("/login")
public class LoginSuccessContorller {
    Map<String, Object> tokenMap = new HashMap<>();

    //跳转统一登陆页面
    @RequestMapping("/loginPage")
    public String loginPage(String callback, String uuid, HttpServletResponse response) {
        //将回调地址 客户端标识放在cookies里面
        Cookie cookie = new Cookie("callback", callback);
        Cookie cookie2 = new Cookie("uuid", uuid);
        response.addCookie(cookie);
        response.addCookie(cookie2);
        return "loginView/login";
    }

    //登陆成功
    @RequestMapping("/loginSuccess")
    public void loginSuccess(HttpServletRequest request, HttpServletResponse response) {
        //取到客户端唯一标识
        String uuid = CookieUtil.getCookie(request, "uuid");
        //创建ticket
        String token = DigestUtils.md5DigestAsHex((EncryptUtil.SALT + uuid + System.currentTimeMillis()).getBytes());
        //存redis,测试60秒过期
        //暂时使用map来测试 后面还用redis缓存
        tokenMap.put(uuid, token);
        //回源url
        String originalUrl = CookieUtil.getCookie(request, "callback") + "?token=" + token;
        //重定向到源url
        try {
            response.sendRedirect(originalUrl);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    //客户端回调检查token
    @RequestMapping("/checkToken/{token}/{uuid}")
    @ResponseBody
    public String checkToken(@PathVariable("token") String token, @PathVariable("uuid") String uuid) {
        Object o = tokenMap.get(uuid);
        if (o != null && o.equals(token)) {
            String tokenNew = DigestUtils.md5DigestAsHex((EncryptUtil.SALT + uuid + System.currentTimeMillis()).getBytes());
            //清除旧token 生成新的token 保证安全性
            System.out.println(tokenNew);
            tokenMap.put(uuid, tokenNew);
            return tokenNew;
        } else {
            return null;
        }
    }
}