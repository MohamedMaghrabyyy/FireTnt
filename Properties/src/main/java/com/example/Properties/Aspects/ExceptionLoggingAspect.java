package com.example.Properties.Aspects;

import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;

@Aspect
@Component
public class ExceptionLoggingAspect {

    @AfterThrowing(pointcut = "execution(* com.example.Properties..*(..))", throwing = "ex")
    public void logAfterThrowing(Exception ex) {
        // You can use a logging framework like Log4j or SLF4J here
        System.err.println("Exception caught: " + ex.getMessage());
        ex.printStackTrace();
    }
}


