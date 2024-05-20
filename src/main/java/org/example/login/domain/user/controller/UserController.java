package org.example.login.domain.user.controller;

import lombok.RequiredArgsConstructor;
import org.example.login.domain.user.dto.UserSignUpDto;
import org.example.login.domain.user.service.UserService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping("/sign-up")
    public String signUp(@RequestBody UserSignUpDto userSignUpDto) throws Exception {
        userService.signUp(userSignUpDto);
        return "회원가입 성공";
    }

    @GetMapping("/oauth2/sign-up")
    public String oauth2SingUp() {
        return "static/oauth2Sign.html";
    }

    @GetMapping("/jwt-test")
    public String jwtTest() {
        return "jwtTest 요청 성공";
    }
}
