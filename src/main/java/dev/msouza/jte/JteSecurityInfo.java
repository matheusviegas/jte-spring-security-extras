package dev.msouza.jte;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.csrf.CsrfToken;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;

public class JteSecurityInfo {

    private final Authentication authentication;
    private final CsrfToken csrfToken;
    private final HttpServletRequest request;
    private final Set<String> simplifiedRoles;

    public JteSecurityInfo(Authentication authentication, CsrfToken csrfToken, HttpServletRequest request) {
        this.authentication = authentication;
        this.csrfToken = csrfToken;
        this.request = request;
        this.simplifiedRoles = Optional.ofNullable(authentication)
                .map(Authentication::getAuthorities)
                .map(AuthUtils::authorityListToStringSet)
                .orElseGet(Collections::emptySet);
    }

    public Authentication getAuthentication() {
        return authentication;
    }

    public CsrfToken getCsrfToken() {
        return csrfToken;
    }

    public Set<String> getSimplifiedRoles() {
        return simplifiedRoles;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

}
