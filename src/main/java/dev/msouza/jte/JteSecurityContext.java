package dev.msouza.jte;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;

import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class JteSecurityContext {

    private static final ThreadLocal<JteSecurityInfo> context = new ThreadLocal<>();

    public static Object getPrincipal() {
        return getFromAuthenticationIfAvailableOrElse(Authentication::getPrincipal, () -> null);
    }

    public static Authentication getAuthentication() {
        return Optional.ofNullable(context.get()).map(JteSecurityInfo::getAuthentication).orElse(null);
    }

    public static <T> T getPrincipalAs(Class<T> principalType) {
        Object principal = getPrincipal();
        return principalType.cast(principal);
    }

    public static boolean hasRole(String role) {
        return getSimplifiedRoles().contains(AuthUtils.removeRolePrefix(role));
    }

    public static boolean hasAnyRole(String... rolesToCheck) {
        return Stream.of(rolesToCheck).anyMatch(role -> getSimplifiedRoles().contains(AuthUtils.removeRolePrefix(role)));
    }

    private static Set<String> getSimplifiedRoles() {
        return Optional.ofNullable(context.get()).map(JteSecurityInfo::getSimplifiedRoles).orElseGet(Collections::emptySet);
    }

    public static boolean hasAllRoles(String... rolesToCheck) {
        return Stream.of(rolesToCheck).allMatch(role -> getSimplifiedRoles().contains(AuthUtils.removeRolePrefix(role)));
    }

    public static String getUsername() {
        return getFromUserDetailsIfAvailableOrElse(UserDetails::getUsername, () -> getFromAuthenticationIfAvailableOrElse(Authentication::getName, () -> null));
    }

    public static boolean isAccountNonExpired() {
        return getFromUserDetailsIfAvailableOrElse(UserDetails::isAccountNonExpired, () -> true);
    }

    public static boolean isAccountNonLocked() {
        return getFromUserDetailsIfAvailableOrElse(UserDetails::isAccountNonLocked, () -> true);
    }

    public static boolean isCredentialsNonExpired() {
        return getFromUserDetailsIfAvailableOrElse(UserDetails::isCredentialsNonExpired, () -> true);
    }

    public static boolean isEnabled() {
        return getFromUserDetailsIfAvailableOrElse(UserDetails::isEnabled, () -> true);
    }

    public static boolean isAuthenticated() {
        return getFromAuthenticationIfAvailableOrElse(Authentication::isAuthenticated, () -> false);
    }

    public static CsrfToken getCsrfToken() {
        return Optional.ofNullable(context.get()).map(JteSecurityInfo::getCsrfToken).orElse(null);
    }

    private static <T> T getFromUserDetailsIfAvailableOrElse(Function<UserDetails, T> extractor, Supplier<T> orElse) {
        Object principal = getPrincipal();
        if (principal instanceof UserDetails userDetails) {
            return extractor.apply(userDetails);
        }

        return orElse.get();
    }

    private static <T> T getFromAuthenticationIfAvailableOrElse(Function<Authentication, T> extractor, Supplier<T> orElse) {
        return Optional.ofNullable(getAuthentication())
                .map(extractor)
                .orElseGet(orElse);
    }

    public static void init(JteSecurityInfo jteSecurityInfo) {
        context.set(jteSecurityInfo);
    }

    public static void clear() {
        context.remove();
    }

}
