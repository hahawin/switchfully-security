package com.cegeka.switchfully.security;

import com.cegeka.switchfully.security.external.authentication.ExternalAuthenticaton;
import com.cegeka.switchfully.security.external.authentication.FakeAuthenticationService;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Collections;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;

public class ArmyAuthenticationProviderTest {
    public static final String PASSWORD = "PASSWORD";
    public static final String USERNAME = "USERNAME";
    @Rule
    public ExpectedException expectedException= ExpectedException.none();
    @Rule public MockitoRule mockitoRule = MockitoJUnit.rule();

    @Mock
    private FakeAuthenticationService authenticationService;
    private ArmyAuthenticationProvider authenticationProvider;

    @Before
    public void setUp() throws Exception {
        authenticationProvider = new ArmyAuthenticationProvider(authenticationService);
    }

    @Test
    public void supports_whenUserNamePasswordAuthToken_thenTrue() {
        assertThat(authenticationProvider.supports(UsernamePasswordAuthenticationToken.class))
                .isTrue();
    }

    @Test
    public void supports_whenAuthentication_thenFalse() {
        assertThat(authenticationProvider.supports(Authentication.class))
                .isFalse();
    }

    @Test
    public void authenticate_WhenUserNameNull_ThenException() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("null", PASSWORD);

        expectedException.expect(BadCredentialsException.class);
        authenticationProvider.authenticate(authenticationToken);
    }

    @Test
    public void authenticate_WhenPasswordNull_ThenException() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(USERNAME, "null");

        expectedException.expect(BadCredentialsException.class);
        authenticationProvider.authenticate(authenticationToken);
    }

    @Test
    public void authenticate_WhenAuthenticationIncorrect_ThenException() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(USERNAME, PASSWORD);
        Mockito.when(authenticationService.getUser(any(), any())).thenReturn(null);

        expectedException.expect(BadCredentialsException.class);
        authenticationProvider.authenticate(authenticationToken);
    }

    @Test
    public void authenticate_WhenAuthenticationCorrect_ThenReturnAuthentication() {
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(USERNAME, PASSWORD);
        ExternalAuthenticaton authenticaton = new ExternalAuthenticaton()
                .withUsername(USERNAME)
                .withPassword(PASSWORD)
                .withRoles(emptyList());
        Mockito.when(authenticationService.getUser(any(), any())).thenReturn(authenticaton);

        Authentication authenticate = authenticationProvider.authenticate(authenticationToken);
        assertThat(authenticate.getPrincipal())
                .isEqualTo(USERNAME);
        assertThat(authenticate.getCredentials())
                .isEqualTo(PASSWORD);
    }
}