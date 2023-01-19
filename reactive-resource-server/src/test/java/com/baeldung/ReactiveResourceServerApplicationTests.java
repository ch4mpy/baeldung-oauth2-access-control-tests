package com.baeldung;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.web.reactive.server.WebTestClient;

import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

@SpringBootTest(webEnvironment = WebEnvironment.MOCK)
@AutoConfigureWebTestClient
class ReactiveResourceServerApplicationTests {
	@Autowired
	WebTestClient api;

	@Test
	void givenUserIsAnonymous_whenGetGreet_thenUnauthorized() throws Exception {
		api.get().uri("/greet").exchange().expectStatus().isUnauthorized();
	}

	@Test
	@WithMockJwtAuth(claims = @OpenIdClaims(preferredUsername = "Tonton Pirate"))
	void givenUserIsAuthenticated_whenGetGreet_thenOk() throws Exception {
		// @formatter:off
		api.get().uri("/greet").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo("Hello Tonton Pirate!");
		// @formatter:on
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
		api.get().uri("/secured-route").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo("Only authorized personnel can read that");
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
		// @formatter:off
		api.get().uri("/secured-method").exchange()
			.expectStatus().isOk().expectBody(String.class).isEqualTo("Only authorized personnel can read that");
		// @formatter:on
	}
}
