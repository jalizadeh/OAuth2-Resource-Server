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
- hasRole("Admin")
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

## Resource Server: Method Level Security
Methods can be secured solely by using "@Secured("ROLE_xxx")" annotation. To activate this feature, in the WebSecurity class, should be activated first. Also "@PreAuthorize("...")" and "@PostAuthorize("...")" can be activated here.

```java
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter{
```

```java
@Secured("ROLE_developer")
@DeleteMapping(path="/{id}")
public String deleteUser(@PathVariable String id) {
	return "Deleted user with id: " + id;
}
```

With "@PreAuthorize" it is possible to set logic using the values sent via the request. For example, **only** the *users with role "developer"* or *the owner of the logged in user*, can invoke this method:

```java
@PreAuthorize("hasAuthority('ROLE_developer') or #id == #jwt.subject")
@DeleteMapping(path="/{id}")
public String deleteUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
	return "Deleted user with id: " + id + " / JWT subject: " + jwt.getSubject();
}
```

"@PostAuthorize" will evaluate after method invocation.

```java
@PostAuthorize("returnObject.id == #jwt.subject")
@GetMapping(path = "/{id}")
public UserRest getUser(@PathVariable String id, @AuthenticationPrincipal Jwt jwt) {
	return new UserRest("6203892e-e66e-42fd-b8b5-ca720ed5045c", "Name", "Lastname");
}
```


## Resource Servers Behind API Gateway
Instead of hitting each microservice, an API Gateway can take the responsibility of detecting the requested resource and transfer it to the appropriate service for us.

Spring Cloud Gateway features:
- Built on Spring Framework 5, Project Reactor and Spring Boot 2.0
- Able to match routes on any request attribute.
- Predicates and filters are specific to routes.
- Circuit Breaker integration.
- Spring Cloud DiscoveryClient integration
- Easy to write Predicates and Filters
- Request Rate Limiting
- Path Rewriting

Add each MS and endpoint, in the `application.properties` file:

```
spring.cloud.gateway.routes[0].id = user-status-check
spring.cloud.gateway.routes[0].uri = http://localhost:8081
spring.cloud.gateway.routes[0].predicates[0] = Path=/users/status/check
spring.cloud.gateway.routes[0].predicates[1] = Method=GET
spring.cloud.gateway.routes[0].filters[0] = RemoveRequestHeader=Cookie
```

## Eureka (Spring Cloud Netflix) Discovery Service
A Discovery Service is needed to let the clients to register themselves in it and all the requests are then transfered via this service.

The Eureka service will run as **server**

```
@EnableEurekaServer
@SpringBootApplication
public class DiscoveryServiceApplication { ... }
```

While other clients, register themselves as register and point to the Discovery Service

```java
@EnableDiscoveryClient
@SpringBootApplication
public class ResourceServerApplication { ... }
```

In "application.properties":

```
spring.application.name=demo-resource-server
eureka.client.serviceUrl.defaultZone = http://localhost:8010/eureka
```


|  Service | Address  |
| :------------ | :------------ |
| Eureka Discovery Service  |  [http://localhost:8010](http://localhost:8010) |
| API Gateway  |  [http://localhost:8082](http://localhost:8082) |
| Authorization Server  |  [http://localhost:8080](http://localhost:8080) |
| Resource Server  |  [http://localhost:8081](http://localhost:8081) |
| Photos Server |  [http://localhost:8090](http://localhost:8090) |
| Albums Server |  [http://localhost:8091](http://localhost:8091) |



## Load Balancing
Applications need to obtain the `port` dynamically

```
server.port=0
```

But with only the line above, Eureka will replace the **new_instance:new_port** with the old one. The solution is to have different **instanceId** for each instance


```
eureka.instance.instance-id=${spring.application.name}:${instanceId:${random.value}}
```

Or provide as a CLI parameter:

```
mvn spring-boot:run -Dspring-boot.run.arguments=--instanceId=javad
```

In API Gateway the endpoints are provided. When a client requests for a resource, the API Gateway recieves and will parse the resource's path and send the parsed request to Eureka (for load balancing between running Resource Servers). Order of running applications will be:

1. Eureka Discovery (Discovery server)
2. API Gateway (registers itself on Eureka)
3. Any other Resource Server


## OAuth 2.0 in MVC Web App
The client needs dependencay [spring-boot-starter-oauth2-client](https://mvnrepository.com/artifact/org.springframework.boot/spring-boot-starter-oauth2-client) and the configuration:

```
spring.security.oauth2.client.registration.mywebclient.client-id=photo-app-webclient
spring.security.oauth2.client.registration.mywebclient.client-secret=<client-secret>
spring.security.oauth2.client.registration.mywebclient.scope=openid, profile, roles
spring.security.oauth2.client.registration.mywebclient.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.mywebclient.redirect-uri=http://localhost:8087/login/oauth2/code/mywebclient

#needed to contact the Authiorization Provider
spring.security.oauth2.client.provider.mywebclient.authorization-uri=http://localhost:8080/realms/appsdeveloperblog/protocol/openid-connect/auth
spring.security.oauth2.client.provider.mywebclient.token-uri=http://localhost:8080/realms/appsdeveloperblog/protocol/openid-connect/token
spring.security.oauth2.client.provider.mywebclient.jwk-set-uri=http://localhost:8080/realms/appsdeveloperblog/protocol/openid-connect/certs
spring.security.oauth2.client.provider.mywebclient.user-info-uri=http://localhost:8080/realms/appsdeveloperblog/protocol/openid-connect/userinfo
spring.security.oauth2.client.provider.mywebclient.user-name-attribute=preferred_username
```

Opening the resource in the browser, will relocate to Keycloak's login page. On successful login, the `OidcUser` can be access in the backend:

```
Name: [javad], 
Granted Authorities: [[ROLE_USER, SCOPE_email, SCOPE_openid, SCOPE_profile]], 
User Attributes: 
[{
	at_hash=xKt23M6B4PGWhG3TwCTTGg, 
	sub=6203892e-e66e-42fd-b8b5-ca720ed5045c, 
	email_verified=true, 
	iss=http://localhost:8080/realms/appsdeveloperblog, 
	typ=ID, 
	preferred_username=javad, 
	given_name=Javad, 
	nonce=kIlcGmk7fgExzLun1BDV9uOXOzOR3iE7yvtj7cmz61I, 
	sid=81bae54b-4369-4d74-a8e9-75d115228e1f, 
	aud=[photo-app-webclient], 
	acr=1, 
	azp=photo-app-webclient, 
	auth_time=2022-09-06T17:18:14Z, 
	name=Javad Alizadeh, 
	exp=2022-09-06T17:23:14Z, 
	session_state=81bae54b-4369-4d74-a8e9-75d115228e1f, 
	family_name=Alizadeh, 
	iat=2022-09-06T17:18:14Z, 
	email=javad@byom.de, 
	jti=4d19a00b-103c-466c-a31a-a0d4a2eafaed
}]

Id Token:
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEQTNOSm5mSHdpWFV1TER4VFJUamRXOTFDbWhlWDNsN0pCc0pkVzhWdmMwIn0.eyJleHAiOjE2NjI0ODY0ODIsImlhdCI6MTY2MjQ4NjE4MiwiYXV0aF90aW1lIjoxNjYyNDg2MTgyLCJqdGkiOiJhMTFhM2MwNy04Zjk5LTRmNGItYjViZS04YTg5YmZhYTgxODUiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAvcmVhbG1zL2FwcHNkZXZlbG9wZXJibG9nIiwiYXVkIjoicGhvdG8tYXBwLXdlYmNsaWVudCIsInN1YiI6IjYyMDM4OTJlLWU2NmUtNDJmZC1iOGI1LWNhNzIwZWQ1MDQ1YyIsInR5cCI6IklEIiwiYXpwIjoicGhvdG8tYXBwLXdlYmNsaWVudCIsIm5vbmNlIjoiMWdaWHcyM19Db1JLd1dMUlZyck9fSUJlYmNyVDF5a0NvVC1jTUJpZTFucyIsInNlc3Npb25fc3RhdGUiOiIxNjk4ZTRjNi04ODhhLTQ3MGEtYThlMi02NDQ2ZTIwYmE3ZjkiLCJhdF9oYXNoIjoiMk92UFItb1QwOE5YSFdIQk5kU3lkQSIsImFjciI6IjEiLCJzaWQiOiIxNjk4ZTRjNi04ODhhLTQ3MGEtYThlMi02NDQ2ZTIwYmE3ZjkiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkphdmFkIEFsaXphZGVoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiamF2YWQiLCJnaXZlbl9uYW1lIjoiSmF2YWQiLCJmYW1pbHlfbmFtZSI6IkFsaXphZGVoIiwiZW1haWwiOiJqYXZhZEBieW9tLmRlIn0.MMknrrwmBlLspbFB1KxJbuhY3zcderz0coh2r01FfETptUuSvSVXJCwxGYOXQ7T8sjvcfpejBuFbg7C21iu0ZITmb9TGts_Co7R5-OLLXJe_wuld97nnS_wwEgKM8ywSkaLsqZgaz90HgUthCs3hovnyxtY0kb4Gn5R2j5zDzSFSctGHGmgjFestRiqqUEc-4b_tlWjCp2bFY_BUF_tLTdqBaq6_XVkqekVNSldbBTXborH9AoYtf3vfytmA5OmkuTcm3lQdKSlSoiTguEYg2PLlMw8FMxFi0jxkkrX2Yf91ghuCiK97zKpRyYlQMUeQWPStlGiji4Eewddsbl-xSQ
```

To get the JWT Access Token and use it for later accesses:

```java
@Autowired
OAuth2AuthorizedClientService  oauth2ClientService;
	
@Autowired
RestTemplate restTemplate;
	
@GetMapping("/albums")
public String getAlbums(Model model, @AuthenticationPrincipal OidcUser principal) {
		
	Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
	OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
		
	OAuth2AuthorizedClient oauth2Client = oauth2ClientService.loadAuthorizedClient(oauthToken.getAuthorizedClientRegistrationId(), oauthToken.getName());
		
	String jwtAccesstoken = oauth2Client.getAccessToken().getTokenValue();
	System.out.println(jwtAccesstoken);
```

