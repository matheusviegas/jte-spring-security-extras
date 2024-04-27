package dev.msouza.jte;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class AuthUtils {

    public static Set<String> authorityListToStringSet(Collection<? extends GrantedAuthority> userAuthorities) {
        Set<String> set = new HashSet<>(userAuthorities.size());

        for (GrantedAuthority authority : userAuthorities) {
            set.add(removeRolePrefix(authority.getAuthority()));
        }

        return set;
    }

    public static String removeRolePrefix(String role) {
        return role.startsWith("ROLE_") ? role.substring(5) : role;
    }

}
