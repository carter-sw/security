package com.example.security1.config;

import com.example.security1.config.auth.PrincipalDetailsService;
import com.example.security1.config.oauth.PrincipalOauth2UserService;
import com.example.security1.filter.MyFilter1;
import com.example.security1.filter.MyFilter3;
import com.example.security1.jwt.JwtAuthenticationFilter;
import com.example.security1.jwt.JwtAuthorizationFilter;
import com.example.security1.repository.UserJwtRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;
import org.springframework.web.filter.CorsFilter;

//1.코드받기(인증),2엑세스토큰(권한),
//3. 사용자프로필 정보 가져와고 4-1 그정보를 토대로 회원가입을 자동으로 진행시키기도함
//4-2 (이메일,전화번호,이름,아이디) 쇼핑몰 -> (집주소),백화점몰 -> (vip등급,일반등급)

@Configuration
@EnableWebSecurity // 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true) //secured 어노테이션 활성화 , preAuthorize 어노테이션 활성화
public class SecurityConfig {

    private final CorsConfig corsConfig;
    private final PrincipalOauth2UserService principalOauth2UserService;
    private final PrincipalDetailsService principalDetailsService;
    private final UserJwtRepository userJwtRepository;




    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

//        http.addFilterBefore(new MyFilter3(), SecurityContextHolderAwareRequestFilter.class); security가 동작전에 myfilter3 가 먼저 동작 기본적으로 이렇게 건다

        http.csrf((csrf) -> csrf.disable());
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // session 사용 안함 (stateless)
                .and()
                .formLogin(f -> f.disable()) // 폼태그(html)를 사용해서 로그인 사용안함
                .httpBasic(h -> h.disable())
                // 클라이언트가 서버에 요청을 보낼 때 사용자 이름과 비밀번호를 인증하는 간단한 방법
                // 클라이언트가 요청을 보낼 때, 인증 정보는 요청 헤더에 Base64로 인코딩되어 포함됩니다. 서버는 이 정보를 확인하여 클라이언트의 요청을 처리하거나 거부합니다.
                // 이 방법은 간단하고 쉽게 구현할 수 있지만, 보안 수준이 낮고 인증 정보가 평문으로 전송되기 때문에 보안에 취약합니다.
                // Http Basic 인증을 사용하지 않도록 Spring Security 구성을 설정
                .authorizeHttpRequests(authorize ->
                        authorize
                                .requestMatchers("/api/v1/user/**")
                                .hasAnyRole("USER", "MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/manager/**")
                                .hasAnyRole("MANAGER", "ADMIN")
                                .requestMatchers("/api/v1/admin/**")
                                .hasRole("ADMIN")
                                .anyRequest().permitAll());// 이외의 요청은 모두 허용함


//        http.authorizeRequests()
//                .requestMatchers("/user/**").authenticated() // 인증만 되면 들어갈수 있는 주소
//                .requestMatchers("/manager/**").hasAnyRole("MANAGER","ADMIN")
//                .requestMatchers("/admin/**").hasAnyRole("ADMIN")
//                .anyRequest().permitAll()
//                .and().formLogin((formLogin)
//                        -> formLogin.loginPage("/loginForm").permitAll()
//                        .loginProcessingUrl("/login") // login 주소가 호출이 되면 시큐리티가 낚아채서 대신 로그인을 진행해줌
//                        .defaultSuccessUrl("/"))
//                        .oauth2Login(oauthLogin -> {
//                            oauthLogin
//                                    .loginPage("/loginForm") // 권한 접근 실패 시 로그인 페이지로 이동
////                                    .defaultSuccessUrl("http://localhost:3000") // 로그인 성공 시 이동할 페이지
////                                    .failureUrl("/oauth2/authorization/google") // 로그인 실패 시 이동 페이지
//                                    .userInfoEndpoint(userInfoEndpoint ->
//                                            userInfoEndpoint.userService(principalOauth2UserService));
//                        });// 사용자 정보 엔드포인트 설정
//                                ; // 사용자 서비스 등록) // 구글 로그인이 완료된 뒤의 후처리가 필요 Tip 코드x,(엑세스토큰 + 사용자프로필정보 O)

//        http.apply(new MyCustomDs()); 아래 코드로 변경
        http.with(new MyCustomDs(), myCustomDs -> myCustomDs.getClass());
        return http.build();

    }

    public class MyCustomDs extends AbstractHttpConfigurer<MyCustomDs, HttpSecurity> { // custom Filter

        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http.addFilter(corsConfig.corsFilter())   // @CrossOrigin(인증x) , 시큐리티 필터에 등록 인증(O)
                    .addFilter(new JwtAuthenticationFilter(authenticationManager))  // AuthenticationManager를 Parameter로 넘겨줘야 함(로그인을 진행하는 데이터이기 때문)
                    .addFilter(new JwtAuthorizationFilter(authenticationManager,userJwtRepository));
            System.out.println("authenticationManager3 : " + authenticationManager);    // log
        }
    }
}

/*
 스프링 시큐리티 필터가 스프링 필터체인에 등록이 됨
 @Bean 어노테이션은 이 메서드가 스프링 컨텍스트에 의해 관리되는 빈(bean)을 생성한다는 것을 의미합니다.
 SecurityFilterChain 타입의 빈을 생성하여 스프링 시큐리티 설정을 정의합니다.
 CSRF(크로스 사이트 요청 위조) 보호 기능을 비활성화합니다.
 테스트 환경이나 내부 시스템에서는 종종 비활성화하지만, 공개적으로 접근 가능한 애플리케이션에서는 보안 위험을 증가시킬 수 있습니다.
 HTTP 요청에 대한 인증 요구 사항을 정의하기 시작합니다.
 "/user/**" 패턴에 일치하는 모든 경로는 인증된(로그인한) 사용자만 접근할 수 있도록 합니다.
 "requestMatchers" 메서드는 특정 요청에 대해 세부적인 설정을 적용할 때 사용됩니다.
 "/manager/**" 패턴에 일치하는 모든 경로는 'ROLE_MANAGER' 또는 'ROLE_ADMIN' 역할을 가진 사용자만 접근할 수 있도록 합니다.
 "access" 메서드는 SpEL(Spring Expression Language)을 사용하여 접근 제어를 더 세밀하게 설정할 수 있습니다.
 "/admin/**" 패턴에 일치하는 모든 경로는 'ROLE_ADMIN' 역할을 가진 사용자만 접근할 수 있도록 합니다.
 이는 관리자 전용 경로에 대한 접근 제어를 설정하는 것입니다.
 위에서 정의되지 않은 모든 다른 요청들은 제한 없이 접근할 수 있도록 합니다.
 즉, 특별한 권한이 필요하지 않은 공개적으로 접근 가능한 경로에 대한 설정입니다.
 .and() 메서드는 현재 HttpSecurity의 설정을 연결하여 계속해서 설정을 추가할 수 있게 해줍니다.
 이 메서드를 사용함으로써, 우리는 설정의 "체인"을 유지하면서, 보다 읽기 쉽고 관리하기 쉬운 코드를 작성할 수 있습니다.
 "formLogin()" 메서드를 호출하여, 폼 기반 인증을 활성화합니다.
 이는 사용자가 아이디와 비밀번호를 입력하여 인증을 수행할 수 있게 하는 전통적인 인증 방식입니다.
 "loginPage()" 메서드를 사용하여, 사용자 정의 로그인 페이지의 경로를 설정합니다.
 기본적으로 스프링 시큐리티는 "/login" 경로에 내장된 로그인 페이지를 제공합니다.
 하지만, 이 메서드를 통해 개발자는 사용자의 경험에 맞춰 커스텀 로그인 페이지를 제공할 수 있습니다.
 이 경로는 우리가 만든 커스텀 로그인 페이지의 URL이 되며, 인증이 필요한 페이지에 접근하려 할 때 사용자를 이 페이지로 리다이렉트합니다.
 위에서 정의된 보안 구성을 기반으로 HttpSecurity 객체를 구성하고, SecurityFilterChain으로 반환합니다.
 이 SecurityFilterChain은 스프링 시큐리티의 필터 체인을 정의하며, 모든 보안 관련 처리를 담당합니다.
*/






