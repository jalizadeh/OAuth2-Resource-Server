# OAuth 2.0 in Spring Boot Applications


## Introduction
OAuth = Open Authorization
OAuth 2.0 is an Authorization framework
OAuth is a delegated authorization framework

### Client Type
We can have different types of clients that need to contact **Authorization Server**. First of all, they need to be registered in the AS, so they are recognized and they can send their **client_id** and **client_secret** to the AS. But not all clients are secure to hold their credentials.

- Confidential *[can keep client_secret safe]*
	- Secure app running on server
- Public *[can not keep the client_id & client_secret safe]*
	- Native apps on user's device
	- Single page browser-based app

### Access Token
- Identifier Type
	- Base-64 encoded
	- In the Authorization Server's DB:
	
|  access_token  |  user_id  | scope  |  expires  |
| :------------: | :------------: | :------------: | :------------: |
| BYL5v5a4s984wF7  | JWeFS12s  | profile, documents  | 159354110  |

- Self-contain the authorization information
	- decodable in [JWT.io](www.jwt.io)
	- header . payload . signature
	- `eyJhbGciOiJSUzI1NiIsImtpZCI6IjFlOWdkazcifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAKfQ.ggW8hZ1EuVLuxNuuIJKX_V8a_OMXzR0EHR9R6jgdqrOOF4daGU96Sr_P6qJp6IcmD3HP99Obi1PRs-cwh3LO-p146waJ8IhehcwL7F09JdijmBqkvPeB2T9CJNqeGpe-gccMg4vfKjkM8FcGvnzZUN4_KSP0aAp1tOJ1zZwgjxqGByKHiOtX7TpdQyHE5lcMiKPXfEIQILVq0pc_E2DzL7emopWoaoZTF_m0_N0YzFC6g6EJbOEoRoSK5hoDalrcvRYLSrQAZZKflyuVCyixEoV9GfNQC3_osjzw2PAithfubEEBLuVVk4XUVrWOLrLl0nx7RkKU8NXNHq-rvKMzqg`


### OpenID Connect

## OAuth 2 Grant Types and Authorization Flows
Is a way an application gets and **access_token**

- Server side web app
	- Authorization Code
	- Password grant *[deprecated]*
- Server side script with no UI
	- Client Credential
- Javascript single page app
	- PKCE Enhanced Authorization Code
	- Implicit Flow *[deprecated]*
	- Password grant *[deprecated]*
- Mobile native app
	- Authorization Code
	- PKCE Enhanced Authorization Code
	- Implicit Flow *[deprecated]*
	- Password grant *[deprecated]*
- Device
	- Device Code

**Refresh Token Grant Type** is used to exchange a **refresh_token** for an **access_token**

### PKCE
Proof Key for Code Exchange
[Java PKCE generator example](https://github.com/simplyi/PKCE/blob/main/src/main/java/com/appsdeveloperblog/pkce/PkceUtil.java)
- Code Challenge
- Code Verifier

### Machine to Machine
grant_type = client_credentials

### Password Grant
Must be only used when the application doesn't support redirect_uri

## Refresh Access Token
grant_type = refresh_token

## Keycloak. The Standalone Authorization Server
Features:
- Open source Identity and Access Management solution
- Supports Single-Sign On (SSO)
- Social Login
- User Federation

### Run
- Download from [here](https://www.keycloak.org/downloads)
- Unzip and go to /bin folder
- run **kc.bat start-dev --http-port=8180**
- open **http://localhost:8180/**

### Client
Each client has some default scopes, so even if they are not provided in the request, AS will use by default. They can be modified
> openid profile email ...

## OAuth Resource Server
The Spring's dependency **spring-boot-starter-oauth2-resource-server** included Spring Security and makes the endpoints secure by default.

RS needs to contact the AS to get the needed tokens. In `application.properties` add one of these:
```
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://localhost:8080/realms/appsdeveloperblog

spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:8080/realms/appsdeveloperblog/protocol/openid-connect/certs
```
To access the resources on the RS, the token is passed via **Authorization: Bearer XXX** format. This [Authentication Principal](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/core/annotation/AuthenticationPrincipal.html) (JWT token) contains the data that can be decrypted by:

```java
@RestController
@RequestMapping("/token")
public class TokenController {

	@GetMapping
	public Jwt getToken(@AuthenticationPrincipal Jwt jwt) {
		return jwt;
	}
}
```

## Resource Server - Scope Based Access Control
Scope is a mechanism in OAuth 2.0 to **limit an application's access to a user's account**. An application can request one or more scopes, this information is then presented to the user in the consent screen, and the access token issued to the application will be limited to the scopes granted.

- The client should have that scope?
- In RS, define the scope-base rule. It must be "SCOPE_xxx", since later Spring Security will add `SCOPE_underline` at the begining of the "scope"

```java
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter{

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
			.authorizeRequests()
				.antMatchers(HttpMethod.GET, "/users/status/check").hasAuthority("SCOPE_profile")
				.anyRequest().authenticated()
			.and()
			.oauth2ResourceServer().jwt();
	}
}
```

## Role Based Access Control with Keycloak
Role is a collection of authorities

| ROLE | User | Admin  | Super Admin  |
| :------------ | :------------ | :------------ | :------------ |
| Privileges /<br/> Authorities |  View Profile <br/> View other users <br/> Edit own profile   |   **User** <br/> Edit profile of other users <br/> Delete other users |  **Admin**  <br/> Edit/Delete other admins  |

In Spring Security:
- Authoriry name = Role name = **ROLE_ADMIN**
- hadRole("Admin")
- hasAuthority("ROLE_ADMIN")

|  ROLES  | AUTHORITIES  |
| :------------ | :------------ |
| ROLE_USER <br/> ROLE_ADMIN <br/> ROLE_DBADMIN  |  READ <br/> WRITE <br/> DELETE  |

In Keycloak different roles can be assigned to users. The user's roles are included in the JWT token:

```json
"realm_access": {
    "roles": [
      "default-roles-appsdeveloperblog",
      "offline_access",
      "developer",
      "uma_authorization"
    ]
  }
```

To let the Spring Security obtain the list of assigned roles, a **Converter** is needed to parse the roles from JWT and put them in **SimpleGrantedAuthority**

```java
public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>>{

	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {
		Map<String, Object> realmAccess = (Map<String, Object>) jwt.getClaims().get("realm_access");
		
		if(realmAccess == null || realmAccess.isEmpty()) {
			return new ArrayList<GrantedAuthority>();
		}
		
		Collection<GrantedAuthority> returnValue = ((List<String>) realmAccess.get("roles"))
				.stream().map(roleName -> "ROLE_" + roleName)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
		
		return returnValue;
	}
}
```

This class is injected in the security configuration

```java
//...
JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
		
		http
			.authorizeRequests()
				.antMatchers(HttpMethod.GET, "/users/status/check")
				//.hasAuthority("SCOPE_profile")
				.hasRole("developer")
				//.hasAuthority("ROLE_developer") //in case of using this cmd
				//.hasAnyRole("developer", "user") //for multiple roles
			.anyRequest().authenticated()
			.and()
			.oauth2ResourceServer()
				.jwt()
				.jwtAuthenticationConverter(jwtAuthenticationConverter);
```