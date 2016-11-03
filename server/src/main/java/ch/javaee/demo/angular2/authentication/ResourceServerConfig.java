package ch.javaee.demo.angular2.authentication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
import org.springframework.security.oauth2.provider.authentication.TokenExtractor;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.core.annotation.Order;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by marco on 02.11.16.
 */

@Configuration
@ConfigurationProperties
@Order(1)
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    private String endpointAuthURL = null;
    private String clientID = null;
    private String clientSecret = null;

    @Value("${auth.url.check_token}")
    public void setEndpointAuthURL(String endpointAuthURL){
        this.endpointAuthURL = endpointAuthURL;
    }

    @Value("${auth.url.clientID}")
    public void setClientID(String clientID){
        this.clientID = clientID;
    }

    @Value("${auth.url.clientSecret}")
    public void setClientSecret(String clientSecret){
        this.endpointAuthURL = clientSecret;
    }

    private TokenExtractor tokenExtractor = new BearerTokenExtractor();
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/protected/**").authenticated().and().authorizeRequests().anyRequest().permitAll();
    }

    private OncePerRequestFilter contextClearer() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
                if (tokenExtractor.extract(httpServletRequest) == null) {
                    SecurityContextHolder.clearContext();
                }
                filterChain.doFilter(httpServletRequest, httpServletResponse);
            }
        };
    }

    @Bean
    @Primary
    public RemoteTokenServices tokenServices () {

        RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
        remoteTokenServices.setCheckTokenEndpointUrl(this.endpointAuthURL);
        remoteTokenServices.setClientId(this.clientID);
        remoteTokenServices.setClientSecret(this.clientSecret);

        return remoteTokenServices;
    }

}
