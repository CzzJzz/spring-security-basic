package me.whiteship.demospringsecurityform.form;

import me.whiteship.demospringsecurityform.Account.Account;
import me.whiteship.demospringsecurityform.Account.AccountContext;
import me.whiteship.demospringsecurityform.common.SecurityLogger;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.stereotype.Service;

import java.util.Collection;

@Service
public class SampleService {

    public void dashboard(){
//        ThreadLocal 강의 부분
//        Account account = AccountContext.getAccount();
//        System.out.println("======================");
//        System.out.println("account = " + account.getUsername());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        System.out.println("======================");
        System.out.println("account = " + userDetails.getUsername());
    }

    @Async
    public void asyncService() {
        SecurityLogger.log("Async Service");
        System.out.println("Async service is called");
    }
}


//http://localhost:8080/account/USER/ktnet/123