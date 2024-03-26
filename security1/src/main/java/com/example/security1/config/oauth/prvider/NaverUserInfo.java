package com.example.security1.config.oauth.prvider;


import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo{

    private Map<String,Object> attributes; // oauth2User.getAttributes()

//    response={id=KgOjhey1MTBn04xSNbqfHl4YwmGPSARWf427sEWfrGM, email=prick94@naver.com, name=김시원}}
    public NaverUserInfo(Map<String,Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getProviderId() {
        return (String) attributes.get("id");
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getName() {
        return (String) attributes.get("name");
    }
}
