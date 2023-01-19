package com.baeldung;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import com.baeldung.ReactiveResourceServerApplication.MessageService;
import com.c4_soft.springaddons.security.oauth2.test.annotations.WithMockJwtAuth;

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
