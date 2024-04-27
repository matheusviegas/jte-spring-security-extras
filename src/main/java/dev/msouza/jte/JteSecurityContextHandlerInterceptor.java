package dev.msouza.jte;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Optional;

@Component
public class JteSecurityContextHandlerInterceptor implements HandlerInterceptor {

    protected static final Log logger = LogFactory.getLog(JteSecurityContextHandlerInterceptor.class);

    @Override
    public boolean preHandle(final HttpServletRequest request, final HttpServletResponse response, final Object handler) {
        try {
            Authentication authentication = Optional.ofNullable(SecurityContextHolder.getContext())
                    .map(SecurityContext::getAuthentication)
                    .orElse(null);
            CsrfToken csrfToken = null;

            if (request.getAttribute("_csrf") instanceof CsrfToken token) {
                csrfToken = token;
            }

            JteSecurityContext.init(new JteSecurityInfo(authentication, csrfToken));
            logger.trace("Initialized JteSecurityContext");
        } catch (Exception e) {
            logger.error("Error creating JteSecurityContext", e);
        }

        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) throws Exception {
        JteSecurityContext.clear();
        logger.trace("Cleared JteSecurityContext");
    }

}