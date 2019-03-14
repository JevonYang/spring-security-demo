package com.yang.security.controller;

import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @PostAuthorize("hasAnyRole('admin','user')")
    @GetMapping(value = "/demo")
    public String hello() {
        return "hello, world!";
    }

    @GetMapping(value = "/test")
    public String test() {
        return "you have role teller";
    }
}
