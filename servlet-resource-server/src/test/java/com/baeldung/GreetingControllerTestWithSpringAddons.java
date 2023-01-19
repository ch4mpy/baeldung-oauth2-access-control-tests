package com.baeldung;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.web.servlet.MockMvc;

import com.baeldung.ServletResourceServerApplication.GreetingController;
import com.baeldung.ServletResourceServerApplication.MessageService;
import com.c4_soft.springaddons.security.oauth2.test.annotations.OpenIdClaims;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

@WebMvcTest(controllers = GreetingController.class, properties = { "server.ssl.enabled=false" })
class GreetingControllerTestWithSpringAddons {

	@MockBean
	MessageService messageService;
	
	@Captor
	ArgumentCaptor<String> whoCaptor;

	@Autowired
	MockMvc api;

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

}
