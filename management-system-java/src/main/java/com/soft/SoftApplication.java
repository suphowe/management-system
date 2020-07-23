package com.soft;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.ServletComponentScan;

@MapperScan("com.soft.dao")
@SpringBootApplication
@ServletComponentScan
public class SoftApplication {

    public static void main(String[] args) {
        SpringApplication.run(SoftApplication.class, args);
    }


}
