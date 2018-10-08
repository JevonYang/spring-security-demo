package com.yang.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping(value = "/demo")
    public String hello() {
        return "hello, world!";
    }

    @GetMapping(value = "/test")
    public String test() {
        return "you hava role teller";
    }
}
