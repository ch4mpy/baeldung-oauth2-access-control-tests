Testing Spring OAuth2 access-control
====================================

In this article, we'll take a deeper dive into testing access-control rules with mocked identities in Spring applications secured with OAuth2.

We'll use `spring-security-test` `MockMvc` request post-processors and `WebTestClient` mutators as well as [`spring-addons`](https://github.com/ch4mpy/spring-addons) test annotations (quite like `@WithMockUser` but for OAuth2 `Authentication` implementations).

Setup
-----

To execute the tests in this article, no authorization-server is needed, but we'd need one if we ever like to run the resource-servers under test and try it with tools like Postman. For the sake of simplicity, we'd use the `master` realm of standalone Keycloak instance running at `https://localhost:8443`, but using any other OIDC authorization-server would require no more than adapting `issuer-uri` property and the authorities mapper bean in Java config (change the private claim(s) to map authorities from in `realmRoles2AuthoritiesConverter` in the samples below).

For more details about Keycloak setup, the best option is [official getting started guides](https://www.keycloak.org/getting-started) (the one for [standalone zip distribution](https://www.keycloak.org/getting-started/getting-started-zip) might be the easiest to start with).

If you want to setup your local [Keycloak instance with TLS](https://www.keycloak.org/server/enabletls) using a self-signed certificate, you might find this Github repo super useful.

The authorization-server you will use should have a minimum of:

*   two declared users, one being granted the `ROLE_AUTHORIZED_PERSONNEL`, and not the other
*   a declared client with authorization-code flow enabled for tools like Postman to get access-tokens on behalf of those users

Tests in this article are designed for two different Spring resource-servers, a servlet and a reactive one, with the same features:

*   be secured with a JWT decoder
*   return `401` if authentication is missing or invalid (expired, wrong issuer, etc.) and `403` if access is denied
*   require current user to be granted with `ROLE_AUTHORIZED_PERSONNEL` to access `/secured-route` and `/secured-method`
*   expose a `/greet` endpoint accessible to any authenticated user
*   use configuration to secure `/secured-route` (with respectively `requestMatcher` and `pathMatcher` for servlet and reactive app)
*   use method annotation to secure `/secured-method`
*   delegate message generation to `MessageService` (which we will mock during unit-tests)
*   at least one method of `MessageService` should be annotated with method-security

You'll find complete code samples (applications & tests) in this [Github repo](https://github.com/ch4mpy/baeldung-oauth2-access-control-tests)

## Servlet application

```java
@SpringBootApplication
public class ServletResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServletResourceServerApplication.class, args);
	}
	
	@Configuration
	@EnableMethodSecurity
	@EnableWebSecurity 
	static class SecurityConf {
		@Bean
		SecurityFilterChain filterChain(HttpSecurity http, Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) throws Exception {
			// @formatter:off
			http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwt -> new JwtAuthenticationToken(jwt, authoritiesConverter.convert(jwt)));
			http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).and().csrf().disable();
			http.exceptionHandling().authenticationEntryPoint((request, response, authException) -> {
				response.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Basic realm=\"Restricted Content\"");
				response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
			});
			
			http.authorizeHttpRequests()
				.requestMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
				.anyRequest().authenticated();
			// @formatter:on

			return http.build();
		}
		
		static interface AuthoritiesConverter extends Converter<Jwt, Collection<GrantedAuthority>> {}
		
		@Bean
		AuthoritiesConverter realmRoles2AuthoritiesConverter() {
			return (Jwt jwt) -> {
				final var realmRoles = Optional.of(jwt.getClaimAsMap("realm_access")).orElse(Map.of());
				@SuppressWarnings("unchecked")
				final var roles = (List<String>) realmRoles.getOrDefault("roles", List.of());
				return roles.stream().map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList();
			};
		}
	}
	
	@Service
	public static class MessageService {

		public String greet(String who) {
			return "Hello %s!".formatted(who);
		}

	    @PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
		public String getSecret() {
			return "Only authorized personnel can read that";
		}
	}
	
	@RestController
	@RequiredArgsConstructor
	public static class GreetingController {
	    private final MessageService messageService;

	    @GetMapping("/greet")
	    public ResponseEntity<String> greet(JwtAuthenticationToken auth) {
	        return ResponseEntity.ok(messageService.greet(auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME)));
	    }

	    @GetMapping("/secured-route")
	    public ResponseEntity<String> securedRoute() {
	        return ResponseEntity.ok(messageService.getSecret());
	    }

	    @GetMapping("/secured-method")
	    @PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
	    public ResponseEntity<String> securedMethod() {
	        return ResponseEntity.ok(messageService.getSecret());
	    }
	}

}
```

## Reactive application

```java
@SpringBootApplication
public class ReactiveResourceServerApplication {

	public static void main(String[] args) {
		SpringApplication.run(ReactiveResourceServerApplication.class, args);
	}
	
	@Configuration
	@EnableWebFluxSecurity
	@EnableReactiveMethodSecurity
	public class SecurityConfig {
	    @Bean
	    SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http, Converter<Jwt, Mono<Collection<GrantedAuthority>>> authoritiesConverter) {
	        http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(jwt -> authoritiesConverter.convert(jwt).map(authorities -> new JwtAuthenticationToken(jwt, authorities)));
	        http.securityContextRepository(NoOpServerSecurityContextRepository.getInstance()).csrf().disable();
	        http.exceptionHandling().accessDeniedHandler(
	            (var exchange, var ex) -> exchange.getPrincipal().flatMap(principal -> {
	                final var response = exchange.getResponse();
	                response.setStatusCode(
	                    principal instanceof AnonymousAuthenticationToken ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN);
	                response.getHeaders().setContentType(MediaType.TEXT_PLAIN);
	                final var dataBufferFactory = response.bufferFactory();
	                final var buffer = dataBufferFactory.wrap(ex.getMessage().getBytes(Charset.defaultCharset()));
	                return response.writeWith(Mono.just(buffer)).doOnError(error -> DataBufferUtils.release(buffer));
	        }));
	        
	        http.authorizeExchange()
	            .pathMatchers("/secured-route").hasRole("AUTHORIZED_PERSONNEL")
	            .anyExchange().authenticated();
	        
	        return http.build();
	    }
		
		static interface AuthoritiesConverter extends Converter<Jwt, Mono<Collection<GrantedAuthority>>> {}
		
		@Bean
		AuthoritiesConverter realmRoles2AuthoritiesConverter() {
			return (Jwt jwt) -> {
				final var realmRoles = Optional.of(jwt.getClaimAsMap("realm_access")).orElse(Map.of());
				@SuppressWarnings("unchecked")
				final var roles = (List<String>) realmRoles.getOrDefault("roles", List.of());
				return Mono.just(roles.stream().map(SimpleGrantedAuthority::new).map(GrantedAuthority.class::cast).toList());
			};
		}
	}
	
	@Service
	public static class MessageService {

		public Mono<String> greet(String who) {
			return Mono.just("Hello %s!".formatted(who));
		}

	    @PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
		public Mono<String> getSecret() {
			return Mono.just("Only authorized personnel can read that");
		}
	}
	
	@RestController
	@RequiredArgsConstructor
	public class GreetingController {
		private final MessageService messageService;

		@GetMapping("/greet")
		public Mono<ResponseEntity<String>> greet(JwtAuthenticationToken auth) {
			return messageService.greet(auth.getToken().getClaimAsString(StandardClaimNames.PREFERRED_USERNAME)).map(ResponseEntity::ok);
		}

		@GetMapping("/secured-route")
		public Mono<ResponseEntity<String>> securedRoute() {
			return messageService.getSecret().map(ResponseEntity::ok);
		}

		@GetMapping("/secured-method")
		@PreAuthorize("hasRole('AUTHORIZED_PERSONNEL')")
		public Mono<ResponseEntity<String>> securedMethod() {
			return messageService.getSecret().map(ResponseEntity::ok);
		}
	}

}
```

Unit-testing with mocked authorizations
---------------------------------------

By "unit-test", we mean a test of a single `@Component` in isolation of any other dependency (which will be mocked instead of being auto-wired). Tested `@Component` could be a `@Controller` in a `@WebMvcTest` or `@WebFluxTest` as well as any other secured `@Service`, `@Repository`, etc. in plain JUnit test.

When tests are run with `MockMvc` or `WebTestClient`, `Authorization` header is not evaluated and there is no need to provide a valid access-token. Instead, we'll use `spring-security-test` `MockMvc` request post-processors and `WebTestClient` mutators or [`spring-addons`](https://github.com/ch4mpy/spring-addons) annotations to configure the test security context with mocked `Authentication` instances.

A common mistake when testing OAuth2 spring applications is using `@WithMockUser`. The issue with this annotation is it populates test security-context with a `UsernamePasswordAuthenticationToken` instance when OAuth2 runtime configuration puts other types of `Authentication` in the security-context:

*   `JwtAuthenticationToken` for resource-server with JWT decoder
*   `BearerTokenAuthentication` for resource-server with access-token introspection (`opaqueToken`)
*   `OAuth2AuthenticationToken` for clients with `oauth2Login`
*   absolutely anything if you choose to return other `Authentication` instance than Spring default one in authentication converter. So, technically, it is possible to have OAuth2 authentication converters return `UsernamePasswordAuthenticationToken` instance and use `@WithMockUser` in tests, but it is a pretty unnatural choice and we won’t demo that here

Be aware that request post-processors and mutators are limited to testing `@Controllers` as it only works with respectively `MockMvc` and `WebTestClient`. To configure test security-context for any component, we'll use `spring-addons` annotations.

## Test setup

`@Controller` unit-tests should be decorated with `@WebMvcTest` for servlet apps and `@WebFluxTest` for reactive ones

As we are writing controller unit-tests, we'll mock `MessageService` and configure a Mockito argument captor to ensure that the value passed to `MessageService::greet` is the content of the right JWT claim.

Last, we'll have `MockMvc` or `WebTestClient` auto-wired.

Here is an empty test class for our servlet controller:

```java
@WebMvcTest(controllers = GreetingController.class)
class GreetingControllerTest {

    @MockBean
    MessageService messageService;
    
    @Captor
    ArgumentCaptor<String> whoCaptor;

    @Autowired
    MockMvc api;

    ...
}
```

And its reactive counterpart:

```java
@WebFluxTest(controllers = GreetingController.class)
class GreetingControllerTest {

    @MockBean
    MessageService messageService;
    
    @Captor
    private ArgumentCaptor<String> whoCaptor;

    @Autowired
    WebTestClient api;

    ...
}
```

Now, let's see how to assert that HTTP status code are matching the specifications we set earlier.

## Unit-testing with `MockMvc` post-processors

To populate the test security-context with `JwtAuthenticationToken`, which is the default `Authentication` type for resource-servers with JWT decoder, we will use `jwt` post-processor for `MockMvc` requests. For that, we will:

*   declare a static import of `org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt`
*   activate and customize it by calling `.with(jwt())` on `MockHttpServletRequestBuilder`

Mind the assertion on HTTP status (`unauthorized`, `forbidden` or `ok`) depending on how the user identity was configured:

```java
	@Test
	void givenUserIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.perform(get("/greet")).andExpect(status().isUnauthorized());
	}

	@Test
	void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
		final var who = "Tonton Pirate";
		final var greeting = "Hello %s!".formatted(who);
		when(messageService.greet(who)).thenReturn(greeting);

		api.perform(get("/greet").with(jwt().jwt(jwt -> jwt.claim("preferred_username", who))))
				.andExpect(status().isOk()).andExpect(content().string(greeting));

		verify(messageService, times(1)).greet(whoCaptor.capture());
		assertEquals(who, whoCaptor.getValue());
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredRoute_thenUnauthorized() throws Exception {
		api.perform(get("/secured-route")).andExpect(status().isUnauthorized());
	}

	@Test
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(secret);

		api.perform(
				get("/secured-route").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL"))))
				.andExpect(status().isOk()).andExpect(content().string(secret));
	}

	@Test
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		api.perform(get("/secured-route").with(jwt().authorities(new SimpleGrantedAuthority("admin")))).andExpect(status().isForbidden());
	}

	@Test
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		api.perform(get("/secured-method").with(jwt().authorities(new SimpleGrantedAuthority("admin")))).andExpect(status().isForbidden());
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredMethod_thenUnauthorized() throws Exception {
		api.perform(get("/secured-method")).andExpect(status().isUnauthorized());
	}

	@Test
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(secret);

		api.perform(
				get("/secured-method").with(jwt().authorities(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL"))))
				.andExpect(status().isOk()).andExpect(content().string(secret));
	}
```

## Unit-testing with `WebTestClient` mutators

In the reactive resource-server, `Authentication` type in security context is same as in the servlet one (it is secured with JwtDecoder too). As a consequence, we will use `mockJwt` mutator for `WebTestClient` in two steps:

*   declare a static import of `org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt`
*   activate and customize it by calling `.mutateWith(mockJwt())` on `WebTestClient`

```java
	@Test
	void givenUserIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get().uri("/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
		final var who = "Tonton Pirate";
		final var greeting = "Hello %s!".formatted(who);
		when(messageService.greet(who)).thenReturn(Mono.just(greeting));

		// @formatter:off
		api.mutateWith(mockJwt().jwt(jwt -> jwt.claim("preferred_username", who)))
			.get().uri("/greet").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo(greeting);
		// @formatter:on

		verify(messageService, times(1)).greet(whoCaptor.capture());
		assertEquals(who, whoCaptor.getValue());
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredRoute_thenUnauthorized() throws Exception {
		api.get().uri("/secured-route").exchange().expectStatus().isUnauthorized();
	}

	@Test
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		// @formatter:off
		api.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("admin")))
			.get().uri("/secured-route").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(Mono.just(secret));

		// @formatter:off
		api.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL")))
			.get().uri("/secured-route").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo(secret);
		// @formatter:on
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredMethod_thenUnauthorized() throws Exception {
		api.get().uri("/secured-method").exchange().expectStatus().isUnauthorized();
	}

	@Test
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		// @formatter:off
		api.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("admin")))
			.get().uri("/secured-method").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(Mono.just(secret));

		// @formatter:off
		api.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_AUTHORIZED_PERSONNEL")))
			.get().uri("/secured-method").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo(secret);
		// @formatter:on
	}
```

## Unit-testing controllers with annotations from `spring-addons`

The same annotations can be used for servlet or reactive apps. The modification to both applications to switch from `spring-security-test` to `spring-addons` annotations are very similar: add a dependency on `com.c4-soft.springaddons:spring-addons-oauth2-test` and replace post-processors and mutators with `@WithMockJwtAuth` annotations.

```java
	@Test
	void givenUserIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.perform(get("/greet")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockJwtAuth(claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
		final var who = "Tonton Pirate";
		final var greeting = "Hello %s!".formatted(who);
		when(messageService.greet(who)).thenReturn(greeting);

		api.perform(get("/greet"))
				.andExpect(status().isOk()).andExpect(content().string(greeting));

		verify(messageService, times(1)).greet(whoCaptor.capture());
		assertEquals(who, whoCaptor.getValue());
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredRoute_thenUnauthorized() throws Exception {
		api.perform(get("/secured-route")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(secret);

		api.perform(
				get("/secured-route"))
				.andExpect(status().isOk()).andExpect(content().string(secret));
	}

	@Test
	@WithMockJwtAuth("admin")
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		api.perform(get("/secured-route")).andExpect(status().isForbidden());
	}

	@Test
	@WithMockJwtAuth("admin")
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		api.perform(get("/secured-method")).andExpect(status().isForbidden());
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredMethod_thenUnauthorized() throws Exception {
		api.perform(get("/secured-method")).andExpect(status().isUnauthorized());
	}

	@Test
	@WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(secret);

		api.perform(
				get("/secured-method"))
				.andExpect(status().isOk()).andExpect(content().string(secret));
	}
```

And the reactive equivalent:

```java
	@Test
	void givenUserIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get().uri("/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithMockJwtAuth(claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
		final var who = "Tonton Pirate";
		final var greeting = "Hello %s!".formatted(who);
		when(messageService.greet(who)).thenReturn(Mono.just(greeting));

		// @formatter:off
		api.get().uri("/greet").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo(greeting);
		// @formatter:on

		verify(messageService, times(1)).greet(whoCaptor.capture());
		assertEquals(who, whoCaptor.getValue());
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredRoute_thenUnauthorized() throws Exception {
		api.get().uri("/secured-route").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithMockJwtAuth("admin")
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenForbidden() throws Exception {
		// @formatter:off
		api.get().uri("/secured-route").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	@WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredRoute_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(Mono.just(secret));

		// @formatter:off
		api.get().uri("/secured-route").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo(secret);
		// @formatter:on
	}

	@Test
	void givenUserIsAnonymous_whenGetSecuredMethod_thenUnauthorized() throws Exception {
		api.get().uri("/secured-method").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithMockJwtAuth("admin")
	void givenUserIsAuthenticatedButNotGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenForbidden() throws Exception {
		// @formatter:off
		api.get().uri("/secured-method").exchange()
			.expectStatus().isForbidden();
		// @formatter:on
	}

	@Test
	@WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecuredMethod_thenOk() throws Exception {
		final var secret = "Secret!";
		when(messageService.getSecret()).thenReturn(Mono.just(secret));

		// @formatter:off
		api.get().uri("/secured-method").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo(secret);
		// @formatter:on
	}
```
Did you note how well annotations fit with the `BDD` paradigm?

Pre-conditions (`Given`) are provided as text context (annotation decorating the test class)
only tested code execution (`When`) and result assertions (`Then`) are in test body

## Unit-testing `MessageService` secured method

To unit test `MessageService:getSecret` access-control, we have a little setup:

*   activate Spring auto-wiring with `@ExtendWith(SpringExtension.class)`
*   `@Import({ MessageService.class })` and `@Autowire` it to get an instrumented instance
*   decorate test class with `@EnableMethodSecurity` in servlet app or `@EnableReactiveMethodSecurity` in reactive one

Note the assertions that an exception is thrown if user is not granted with `ROLE_AUTHORIZED_PERSONNEL`:

```java
@Import({ MessageService.class })
@ExtendWith(SpringExtension.class)
@EnableMethodSecurity
class MessageServiceTest {
	@Autowired
	MessageService messageService;

	@Test
	void givenUserIsAnonymous_whenGetSecret_thenThrowsMissingAuthentication() {
		assertThrows(AuthenticationCredentialsNotFoundException.class, () -> messageService.getSecret());
	}

	@Test
	@WithMockJwtAuth("admin")
	void givenUserIsAuthenticatedButIsNotGrantedWithRoleAuthorizedPersonnel_whenGetSecret_thenThrowsAccessDenied() {
		assertThrows(AccessDeniedException.class, () -> messageService.getSecret());
	}

	@Test
	@WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecret_thenReturnSecret() {
		assertEquals("Only authorized personnel can read that", messageService.getSecret());
	}
}
```
And the reactive equivalent:
```java
@Import({ MessageService.class })
@ExtendWith(SpringExtension.class)
@EnableReactiveMethodSecurity
class MessageServiceTest {
	@Autowired
	MessageService messageService;

	@Test
	void givenUserIsAnonymous_whenGetSecret_thenThrowsMissingAuthentication() {
		assertThrows(AccessDeniedException.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithMockJwtAuth("admin")
	void givenUserIsAuthenticatedButIsNotGrantedWithRoleAuthorizedPersonnel_whenGetSecret_thenThrowsAccessDenied() {
		assertThrows(AccessDeniedException.class, () -> messageService.getSecret().block());
	}

	@Test
	@WithMockJwtAuth("ROLE_AUTHORIZED_PERSONNEL")
	void givenUserIsGrantedWithRoleAuthorizedPersonnel_whenGetSecret_thenReturnSecret() {
		assertEquals("Only authorized personnel can read that", messageService.getSecret().block());
	}
}
```

Did you spot the slight difference in the exception thrown between servlet and reactive apps in case of unauthorized users?

Integration-testing with mocked authorizations
----------------------------------------------

Spring-boot application can be tested with actual components autowired but using mocked identities (and `MockMvc` or `WebTestClient`). The tests themself and options to populate test security-context with mocked identities are the same as for controllers unit-tests. Only test setup changes:

*   no more components mocks nor argument matchers
*   `@SpringBootTest(webEnvironment = WebEnvironment.MOCK)` is used instead of `@WebMvcTest` or `@WebFluxTest` (`MOCK` environment is used with `MockMvc` or `ReactiveJwtDecoder` and mocked authorizations)
*   decorate explicitly test class with `@AutoConfigureMockMvc` or `@AutoConfigureWebTestClient` (this is done implicitly by `@WebMvcTest` and `@WebFluxTest`) so that `MockMvc` or `WebTestClient` can be auto-wired

```java
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureMockMvc
class ServletResourceServerApplicationTests {
    @Autowired
    MockMvc api;
    
    // Test structure and mocked identities options are the same as seen before in unit-tests
}
```
```java
@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
class ReactiveResourceServerApplicationTests {
    @Autowired
    WebTestClient api;
    
    // Test structure and mocked identities options are the same as seen before in unit-tests
}
```

Of course, this kind of test is slower and much more fragile than unit-tests and should be used with caution, maybe with a lower coverage than `@WebMvcTest` or `@WebFluxTest`, just to assert that auto-wiring and inter-component communication work.

To go further
-------------

In this article, we used resource-servers (applications containing `@Controller` returning `@ResponseBody` or their `@RestController` shorthand) secured with a JWT decoder. By default, such applications have `JwtAuthenticationToken` instances in security-context, reason for using `@WithMockJwtAuth`, `jwt()` post-processor and `mockJwt()` mutator.

As seen earlier, Spring OAuth2 security-context can be configured with other types of `Authentication`, in which case, we should use other annotations, post-processors or mutators in tests. For instance:

*   in case of resource-servers with token introspection, default `Authentication` type is `BearerTokenAuthentication` and tests should use `@WithMockBearerTokenAuthentication`, `opaqueToken()` or `mockOpaqueToken()` (all instanciate a `BearerTokenAuthentication`)
*   in case of clients (applications with `oauth2Login` and `@Controller` methods returning template names), default `Authentication` type is `OAuth2AuthenticationToken` and we would use `@WithOAuth2Login`, `@WithOidcLogin`, `oauth2Login()`, `oidcLogin()`, `mockOAuth2Login()` or `mockOidcLogin()`
*   in case of custom `Authentication` (configured with `http.oauth2ResourceServer().jwt().jwtAuthenticationConverter(...)` or whatever), we'll have to provide our own unit-test tooling, which is not that complicated when using [`spring-addons` implementations as sample](https://github.com/ch4mpy/spring-addons/blob/master/spring-addons-oauth2-test/src/main/java/com/c4_soft/springaddons/security/oauth2/test/annotations/OpenId.java). You can find a sample of such a custom `Authentication` and dedicated test annotation in [spring-addons tutorials](https://github.com/ch4mpy/spring-addons/tree/master/samples/tutorials)
