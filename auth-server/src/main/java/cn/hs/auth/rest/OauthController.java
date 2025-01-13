package cn.hs.auth.rest;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OauthController {
    //打印返回的code
    @RequestMapping("/login/oauth2/code/demo-client")
    public String showCode(String code) {
        System.out.println("code: " + code);
        return code;
    }
}
