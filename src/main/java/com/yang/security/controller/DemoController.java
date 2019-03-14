package com.yang.security.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

/**
 * 用于测试的一些controller
 * @author jevon
 */
@RestController
public class DemoController {

    @PreAuthorize("hasAnyAuthority('ROLE_ADMIN')")
    @GetMapping(value = "/demo")
    public String hello() {
        return "hello, world!";
    }

    @GetMapping(value = "/test")
    public String test() {
        return "you have role teller";
    }

    @RequestMapping(value = "/user", method = RequestMethod.POST)
    public Principal user(Principal user) {
        System.out.println(user.toString());
        return user;
    };
}
