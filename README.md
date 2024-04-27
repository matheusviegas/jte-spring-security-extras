# JTE Spring Security Extras

This library is a helper package that facilitates the use of Spring Security Authentication and CSRF protection information within JTE templates.

## Usage:

### Import the dependency

```xml
<dependency>
    <groupId>dev.msouza</groupId>
    <artifactId>jte-spring-security-extras</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Import the utility methods

```java
@import static dev.msouza.jte.JteSecurityContext.*
```

Example:

```java
@import static dev.msouza.jte.JteSecurityContext.*

@if(isAuthenticated())
    <p>Autenticado</p>
@endif
```

## Available Methods

All of the methods listed bellow are available as static methods inside JteSecurityContext and can be called from the templates.

- `Object getPrincipal()`
- `Authentication getAuthentication()`
- `<T> T getPrincipalAs(Class<T> principalType)`
- `boolean hasRole(String role)`
- `boolean hasAnyRole(String... rolesToCheck)`
- `boolean hasAllRoles(String... rolesToCheck)`
- `String getUsername()`
- `boolean isAccountNonExpired()`
- `boolean isAccountNonLocked()`
- `boolean isCredentialsNonExpired()`
- `boolean isEnabled()`
- `boolean isAuthenticated()`
- `CsrfToken getCsrfToken()`