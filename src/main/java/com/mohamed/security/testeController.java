package com.mohamed.security;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class testeController {
    @GetMapping("/nonsecure")
    public String getData(){
        return "Hello World ";
    }
    @GetMapping("/secure")
    public String getSecureData(){
        return "Hello World  secure";
    }
}
