package cn.hs.client.rest;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OauthController {
    @GetMapping("/")
    public String index(Model model, OAuth2AuthenticationToken authentication) {
        model.addAttribute("userName", authentication.getName());
        model.addAttribute("authorities", authentication.getAuthorities());
        return "index";
    }

    @GetMapping("/login/oauth2/code/my-client")
    public String callback(@RequestParam String code) {
        // 可以在这里打印或处理授权码
        System.out.println("Authorization Code: " + code);
        return code;
    }
}
