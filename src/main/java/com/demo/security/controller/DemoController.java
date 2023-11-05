package com.demo.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/demo")
public class DemoController {
    @GetMapping("/public")
    public String publicEndpoint() {
        return "<h1>Hello from public endpoind</h1>";
    }

    @GetMapping("/private")
    public String privateEndpoint() {
        return "<h1>Hello from protected endpoind</h1>";
    }
}
