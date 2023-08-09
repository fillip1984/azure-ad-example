package org.home.tutorial.azureadexample;

import java.util.HashSet;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security config
 */
@Configuration
@EnableWebSecurity

public class SecurityConfig {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http.authorizeRequests()
                .antMatchers( "/oauth2/**", "/login/**" ).permitAll()
                .antMatchers("/user_survey").hasRole("USER")
                .antMatchers("/admin_survey").hasRole("ADMIN")
                .antMatchers("/survey").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .userInfoEndpoint()
                .userAuthoritiesMapper(this.userAuthoritiesMapper())
                .and()
                .defaultSuccessUrl( "/home" );
        return http.build();
        // @formatter:on
    }

    // ideas:
    // https://stackoverflow.com/questions/58205510/spring-security-mapping-oauth2-claims-with-roles-to-secure-resource-server-endp
    // https://stackoverflow.com/questions/55609083/how-to-set-user-authorities-from-user-claims-return-by-an-oauth-server-in-spring
    // https://stackoverflow.com/questions/19525380/difference-between-role-and-grantedauthority-in-spring-security
    // https://stackoverflow.com/questions/60751605/how-does-spring-security-inject-principal-into-controller
    private GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();
            logger.info("authoritiesauthoritiesauthoritiesauthorities");
            authorities.forEach((authority -> {
                if (authority instanceof OidcUserAuthority) {

                    OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                    OidcIdToken idToken = oidcUserAuthority.getIdToken();

                    if (!idToken.hasClaim("groups")) {
                        throw new RuntimeException("Oauth ID token was missing group attribute");
                    }

                    var groups = idToken.getClaimAsStringList("groups");
                    groups.forEach(group -> {
                        // for some reason I only get groups as oid and not name so I have to map them
                        // specificially to the role
                        if (group.equals("9d72d8ed-2e97-44d3-bb52-35f7c552efa5")) {
                            mappedAuthorities.add(new SimpleGrantedAuthority(("ROLE_ADMIN")));
                        } else if (group.equals("fbea1c74-c985-4ed8-b2b8-4c5e56a7cbda")) {
                            mappedAuthorities.add(new SimpleGrantedAuthority(("ROLE_USER")));
                        } else {
                            mappedAuthorities.add(new SimpleGrantedAuthority(("ROLE_" + group)));
                        }
                    });
                } else if (authority instanceof OAuth2UserAuthority) {
                    // TODO: not necessary? or maybe trace or debug level logging
                    OAuth2UserAuthority oAuth2UserAuthority = (OAuth2UserAuthority) authority;
                    logger.info("oauth2UserAuthority: {}", oAuth2UserAuthority);
                } else {
                    // TODO: not necessary? or maybe trace or debug level logging or warn?
                    logger.info("Not oidc/oauth user authority");
                }
            }));
            // fill in your authorities
            logger.info("mapped roles: " + mappedAuthorities.toString());
            return mappedAuthorities;
        };
    }

}
