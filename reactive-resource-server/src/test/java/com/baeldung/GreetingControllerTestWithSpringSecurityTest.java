package com.baeldung;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.baeldung.ReactiveResourceServerApplication.GreetingController;
import com.baeldung.ReactiveResourceServerApplication.MessageService;

import reactor.core.publisher.Mono;

@WebFluxTest(controllers = GreetingController.class, properties = { "server.ssl.enabled=false" })
class GreetingControllerTestWithSpringSecurityTest {

	@MockBean
	MessageService messageService;
	
	@Captor
	private ArgumentCaptor<String> whoCaptor;

	@Autowired
	WebTestClient api;

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

}

