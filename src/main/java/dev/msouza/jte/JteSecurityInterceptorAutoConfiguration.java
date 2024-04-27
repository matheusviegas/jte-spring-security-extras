package dev.msouza.jte;


import gg.jte.TemplateEngine;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@AutoConfiguration
@ConditionalOnClass({TemplateEngine.class})
@ConditionalOnProperty(name = "jte.security.autoconfigure", havingValue = "true", matchIfMissing = true)
public class JteSecurityInterceptorAutoConfiguration implements WebMvcConfigurer {

    private static final Log logger = LogFactory.getLog(JteSecurityInterceptorAutoConfiguration.class);

    @Override
    public void addInterceptors(final InterceptorRegistry registry) {
        registry.addInterceptor(new JteSecurityContextHandlerInterceptor());
        logger.trace("Registered JteSecurityContextHandlerInterceptor in the InterceptorRegistry");
    }

}