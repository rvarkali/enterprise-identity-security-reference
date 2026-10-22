package dev.portfolio.iam.authorization;

import dev.portfolio.iam.PrincipalResolver;
import dev.portfolio.iam.SecurityConfig;
import dev.portfolio.iam.TenantController;
import dev.portfolio.iam.resources.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import static dev.portfolio.iam.authorization.AuthorizationResult.*;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest({ResourceController.class, TenantController.class})
@Import({SecurityConfig.class, ResourceReadService.class, PrincipalResolver.class, AuthorizationService.class})
class ResourceEndpointsTest {
  static final UUID ALICE = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  static final UUID BOB = UUID.fromString("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
  static final UUID ACME = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000001");
  static final UUID GLOBEX = UUID.fromString("bbbbbbbb-0000-4000-8000-000000000001");
  static final UUID PROJECT = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000002");
  static final UUID DOCUMENT = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000003");
  static final String ISSUER = "http://localhost:8081/realms/iam-reference";
  static final String SUBJECT = "11111111-1111-4111-8111-111111111111";
  @Autowired MockMvc mvc;
  @MockitoBean JdbcTemplate jdbc;
  @MockitoBean ResourceRepository resources;
  @MockitoBean OpenFgaClient fga;
  @MockitoBean OpaClient opa;
  @MockitoBean JwtDecoder jwtDecoder;

  @BeforeEach void setUp() {
    when(opa.checkRead(any(), nullable(String.class))).thenReturn(ALLOW);
    identity(List.of(ALICE));
    when(resources.findProject(PROJECT)).thenReturn(Optional.of(
      new ResourceRepository.Project(PROJECT, ACME, "acme", "sensitive-project-name")));
    when(resources.findDocument(DOCUMENT)).thenReturn(Optional.of(
      new ResourceRepository.Document(DOCUMENT, ACME, "acme", PROJECT, "sensitive-document-name", "CONFIDENTIAL")));
    when(resources.hasMembership(ALICE, ACME)).thenReturn(true);
    eligibility("ACTIVE", "ACTIVE", "ACTIVE");
    when(fga.check(ALICE, "project:" + PROJECT, "can_view")).thenReturn(ALLOW);
    when(fga.check(ALICE, "document:" + DOCUMENT, "can_view")).thenReturn(ALLOW);
  }

  private void identity(List<UUID> ids) {
    when(jdbc.query(contains("principal_identities"), org.mockito.ArgumentMatchers.<RowMapper<UUID>>any(),
      eq(ISSUER), eq(SUBJECT))).thenReturn(ids);
  }

  private void eligibility(String principal, String tenant, String membership) {
    when(jdbc.queryForList(AuthorizationService.MEMBERSHIP_SQL, ALICE, "acme")).thenReturn(List.of(Map.of(
      "principal_status", principal, "tenant_status", tenant, "membership_status", membership)));
  }

  private UUID id(String type) { return type.equals("projects") ? PROJECT : DOCUMENT; }
  private String object(String type) { return (type.equals("projects") ? "project:" : "document:") + id(type); }
  private ResultActions read(String type) throws Exception {
    return mvc.perform(get("/api/v1/" + type + "/" + id(type))
      .with(jwt().jwt(token -> token.issuer(ISSUER).subject(SUBJECT))));
  }
  private void denied(ResultActions response, int status) throws Exception {
    response.andExpect(status().is(status)).andExpect(jsonPath("$.name").doesNotExist())
      .andExpect(content().string(not(containsString("sensitive-"))))
      .andExpect(content().string(not(containsString("CONFIDENTIAL"))))
      .andExpect(content().string(not(containsString("private database details"))));
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void authorizedReadUsesUuidAndInternalPrincipal(String type) throws Exception {
    read(type).andExpect(status().isOk()).andExpect(jsonPath("$.id").value(id(type).toString()))
      .andExpect(jsonPath("$.tenantId").value(ACME.toString())).andExpect(jsonPath("$.tenantSlug").value("acme"));
    var order = inOrder(fga, opa);
    order.verify(fga).check(ALICE, object(type), "can_view");
    order.verify(opa).checkRead(type.equals("projects") ? AuthorizationService.ResourceType.PROJECT
      : AuthorizationService.ResourceType.DOCUMENT, type.equals("projects") ? null : "CONFIDENTIAL");
    if (type.equals("documents")) {
      read(type).andExpect(jsonPath("$.projectId").value(PROJECT.toString()))
        .andExpect(jsonPath("$.classification").value("CONFIDENTIAL"));
    }
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void sameTenantWithoutPermissionReturns403AndNoData(String type) throws Exception {
    when(fga.check(ALICE, object(type), "can_view")).thenReturn(DENY);
    denied(read(type), 403);
    verifyNoInteractions(opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void crossTenantIsHiddenBeforeOpenFga(String type) throws Exception {
    when(resources.findProject(PROJECT)).thenReturn(Optional.of(
      new ResourceRepository.Project(PROJECT, GLOBEX, "globex", "sensitive-project-name")));
    when(resources.findDocument(DOCUMENT)).thenReturn(Optional.of(
      new ResourceRepository.Document(DOCUMENT, GLOBEX, "globex", PROJECT, "sensitive-document-name", "CONFIDENTIAL")));
    denied(mvc.perform(get("/api/v1/" + type + "/" + id(type))
      .param("tenantSlug", "acme").param("tenantId", ACME.toString()).header("X-Tenant-Id", ACME)
      .with(jwt().jwt(token -> token.issuer(ISSUER).subject(SUBJECT).claim("tenantSlug", "acme")))), 404);
    verify(resources).hasMembership(ALICE, GLOBEX);
    verifyNoInteractions(fga, opa);
    verify(jdbc, never()).queryForList(anyString(), any(UUID.class), anyString());
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void missingResourceReturns404(String type) throws Exception {
    when(resources.findProject(PROJECT)).thenReturn(Optional.empty());
    when(resources.findDocument(DOCUMENT)).thenReturn(Optional.empty());
    denied(read(type), 404);
    verify(resources, never()).hasMembership(any(), any());
    verifyNoInteractions(fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void inactiveOrUnprovisionedPrincipalReturns403BeforeLookup(String type) throws Exception {
    identity(List.of()); // Shared resolver SQL filters p.status='ACTIVE'.
    denied(read(type), 403);
    verifyNoInteractions(resources, fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void inactiveMembershipReturns404WithoutOpenFga(String type) throws Exception {
    when(resources.hasMembership(ALICE, ACME)).thenReturn(false);
    denied(read(type), 404);
    verifyNoInteractions(fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void inactiveTenantReturns404WithoutOpenFga(String type) throws Exception {
    when(resources.hasMembership(ALICE, ACME)).thenReturn(false);
    denied(read(type), 404);
    verifyNoInteractions(fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void missingMembershipReturns404WithoutOpenFga(String type) throws Exception {
    when(resources.hasMembership(ALICE, ACME)).thenReturn(false);
    denied(read(type), 404);
    verifyNoInteractions(fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void principalDisabledAfterIdentityResolutionReturns404(String type) throws Exception {
    // Identity was ACTIVE when resolved; the membership gate observes the later disable.
    when(resources.hasMembership(ALICE, ACME)).thenReturn(false);
    denied(read(type), 404);
    verifyNoInteractions(fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void revokedMembershipDuringAuthorizationRemainsConcealed(String type) throws Exception {
    when(resources.hasMembership(ALICE, ACME)).thenReturn(true, false);
    eligibility("ACTIVE", "ACTIVE", "DISABLED");
    denied(read(type), 404);
    verifyNoInteractions(fga, opa);
  }

  @Test void membershipRecheckFailureReturns503WithoutData() throws Exception {
    when(resources.hasMembership(ALICE, ACME)).thenReturn(true)
      .thenThrow(new DataAccessResourceFailureException("private database details"));
    when(fga.check(ALICE, "project:" + PROJECT, "can_view")).thenReturn(DENY);
    denied(read("projects"), 503);
  }

  @ParameterizedTest @EnumSource(value = AuthorizationResult.class,
    names = {"UNAVAILABLE", "TIMEOUT", "INVALID_CONFIGURATION", "INVALID_RESPONSE"})
  void openFgaFailuresReturn503(AuthorizationResult failure) throws Exception {
    for (String type : List.of("projects", "documents")) {
      when(fga.check(ALICE, object(type), "can_view")).thenReturn(failure);
      denied(read(type), 503);
    }
    verifyNoInteractions(opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void databaseUnavailableDuringLookupReturns503(String type) throws Exception {
    when(resources.findProject(PROJECT)).thenThrow(new DataAccessResourceFailureException("private database details"));
    when(resources.findDocument(DOCUMENT)).thenThrow(new DataAccessResourceFailureException("private database details"));
    denied(read(type), 503);
    verifyNoInteractions(fga, opa);
  }

  @Test void databaseUnavailableDuringIdentityResolutionReturns503() throws Exception {
    when(jdbc.query(contains("principal_identities"), org.mockito.ArgumentMatchers.<RowMapper<UUID>>any(),
      eq(ISSUER), eq(SUBJECT))).thenThrow(new DataAccessResourceFailureException("private database details"));
    denied(read("projects"), 503);
    verifyNoInteractions(resources, fga, opa);
  }

  @Test void databaseUnavailableDuringMembershipLookupReturns503() throws Exception {
    when(resources.hasMembership(ALICE, ACME)).thenThrow(new DataAccessResourceFailureException("unavailable"));
    denied(read("documents"), 503);
    verifyNoInteractions(fga, opa);
  }

  @Test void databaseUnavailableDuringAuthorizationReturns503() throws Exception {
    when(jdbc.queryForList(AuthorizationService.MEMBERSHIP_SQL, ALICE, "acme"))
      .thenThrow(new DataAccessResourceFailureException("unavailable"));
    denied(read("projects"), 503);
    verifyNoInteractions(fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void invalidUuidReturns400BeforeDependencies(String type) throws Exception {
    denied(mvc.perform(get("/api/v1/" + type + "/not-a-uuid")
      .with(jwt().jwt(token -> token.issuer(ISSUER).subject(SUBJECT)))), 400);
    verifyNoInteractions(jdbc, resources, fga, opa);
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void callerCannotOverrideIdentityOrTenant(String type) throws Exception {
    when(fga.check(ALICE, object(type), "can_view")).thenReturn(DENY);
    denied(mvc.perform(get("/api/v1/" + type + "/" + id(type))
      .param("principalId", BOB.toString()).param("tenantId", GLOBEX.toString()).param("tenantSlug", "globex")
      .header("X-Principal-Id", BOB).header("X-Tenant-Id", GLOBEX)
      .contentType("application/json").content("{\"principalId\":\"" + BOB + "\",\"tenantSlug\":\"globex\"}")
      .with(jwt().jwt(token -> token.issuer(ISSUER).subject(SUBJECT)
        .claim("principalId", BOB.toString()).claim("tenantSlug", "globex")))), 403);
    verify(resources, times(2)).hasMembership(ALICE, ACME);
    verify(jdbc).queryForList(AuthorizationService.MEMBERSHIP_SQL, ALICE, "acme");
    verify(fga).check(ALICE, object(type), "can_view");
  }

  @ParameterizedTest @ValueSource(strings = {"projects", "documents"})
  void unauthenticatedRequestsReturn401(String type) throws Exception {
    denied(mvc.perform(get("/api/v1/" + type + "/" + id(type))), 401);
    verifyNoInteractions(jdbc, resources, fga, opa);
  }

  @ParameterizedTest @EnumSource(value = AuthorizationResult.class,
    names = {"DENY", "UNAVAILABLE", "TIMEOUT", "INVALID_CONFIGURATION", "INVALID_RESPONSE"})
  void opaDenialsAndFailuresNeverReturnResourceData(AuthorizationResult result) throws Exception {
    when(opa.checkRead(any(), nullable(String.class))).thenReturn(result);
    for (String type : List.of("projects", "documents")) {
      denied(read(type), result == DENY ? 403 : 503);
    }
  }

  @Test void nullOpaDecisionFailsClosed() throws Exception {
    when(opa.checkRead(any(), nullable(String.class))).thenReturn(null);
    denied(read("projects"), 503);
  }

  @Test void documentContextComesFromDatabaseNotCallerClaims() throws Exception {
    when(opa.checkRead(AuthorizationService.ResourceType.DOCUMENT, "CONFIDENTIAL")).thenReturn(DENY);
    denied(mvc.perform(get("/api/v1/documents/" + DOCUMENT)
      .param("classification", "PUBLIC").param("assurance", "mfa").header("X-Assurance", "mfa")
      .with(jwt().jwt(token -> token.issuer(ISSUER).subject(SUBJECT)
        .claim("acr", "1").claim("assurance", "mfa").claim("classification", "PUBLIC")))), 403);
    verify(opa).checkRead(AuthorizationService.ResourceType.DOCUMENT, "CONFIDENTIAL");
  }

  @ParameterizedTest @ValueSource(booleans = {true, false})
  void mfaShapedClaimsCannotBypassEarlierGates(boolean tenantDenied) throws Exception {
    if (tenantDenied) when(resources.hasMembership(ALICE, ACME)).thenReturn(false);
    else when(fga.check(ALICE, "document:" + DOCUMENT, "can_view")).thenReturn(DENY);
    denied(mvc.perform(get("/api/v1/documents/" + DOCUMENT)
      .header("X-Assurance", "test:verified-mfa")
      .with(jwt().jwt(token -> token.issuer(ISSUER).subject(SUBJECT)
        .claim("acr", "2").claim("amr", List.of("pwd", "otp"))
        .claim("assurance", "test:verified-mfa")))), tenantDenied ? 404 : 403);
    verifyNoInteractions(opa);
    if (tenantDenied) verifyNoInteractions(fga);
  }

  @ParameterizedTest @ValueSource(strings = {"ALLOW", "TENANT", "FGA", "OPA", "FAILURE"})
  void structuredSecurityEventIsSingleAndRedacted(String scenario) throws Exception {
    var logger=(ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger("security.authorization");
    var appender=new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();
    appender.start();logger.addAppender(appender);
    try {
      int expected=200;
      if(scenario.equals("TENANT")) {when(resources.hasMembership(ALICE,ACME)).thenReturn(false);expected=404;}
      if(scenario.equals("FGA")) {when(fga.check(ALICE,"document:"+DOCUMENT,"can_view")).thenReturn(DENY);expected=403;}
      if(scenario.equals("OPA")) {when(opa.checkRead(any(),nullable(String.class))).thenReturn(DENY);expected=403;}
      if(scenario.equals("FAILURE")) {when(opa.checkRead(any(),nullable(String.class))).thenReturn(UNAVAILABLE);expected=503;}
      mvc.perform(get("/api/v1/documents/"+DOCUMENT).header("X-Request-ID","untrusted-secret")
        .header("X-Principal-Id",BOB.toString())
        .with(jwt().jwt(token->token.issuer(ISSUER).subject(SUBJECT).claim("secret","token-secret"))))
        .andExpect(status().is(expected));
      org.junit.jupiter.api.Assertions.assertEquals(1,appender.list.size());
      String line=appender.list.getFirst().getFormattedMessage();
      org.junit.jupiter.api.Assertions.assertTrue(line.contains("event_type=RESOURCE_AUTHORIZATION"));
      org.junit.jupiter.api.Assertions.assertTrue(line.contains("principal_id="+ALICE));
      String outcome=expected==200?"ALLOW":expected==503?"ERROR":"DENY";
      org.junit.jupiter.api.Assertions.assertTrue(line.contains("outcome="+outcome));
      String reason=switch(scenario) {
        case "ALLOW" -> "ALL_GATES_PASSED"; case "TENANT" -> "RESOURCE_OR_ELIGIBILITY";
        case "FGA" -> "RELATIONSHIP_OR_ELIGIBILITY_DENY"; case "OPA" -> "OPA_DENY";
        default -> "DEPENDENCY_OR_INTERNAL_FAILURE";
      };
      org.junit.jupiter.api.Assertions.assertTrue(line.contains("reason="+reason));
      for(String forbidden:List.of("untrusted-secret","token-secret",SUBJECT,ISSUER,BOB.toString(),"sensitive-document-name","CONFIDENTIAL"))
        org.junit.jupiter.api.Assertions.assertFalse(line.contains(forbidden));
      if(expected!=200) {
        org.junit.jupiter.api.Assertions.assertFalse(line.contains(ACME.toString()));
        org.junit.jupiter.api.Assertions.assertFalse(line.contains(DOCUMENT.toString()));
      }
      String correlation=line.split("correlation_id=")[1].split(" ")[0];
      java.util.UUID.fromString(correlation);
      org.junit.jupiter.api.Assertions.assertNull(appender.list.getFirst().getThrowableProxy());
    } finally {logger.detachAppender(appender);appender.stop();}
  }

  @Test void existingMeEndpointStillUsesIssuerSubjectResolver() throws Exception {
    mvc.perform(get("/api/v1/me").with(jwt().jwt(token -> token.issuer(ISSUER).subject(SUBJECT))))
      .andExpect(status().isOk()).andExpect(jsonPath("$.principalId").value(ALICE.toString()));
    verify(jdbc).query(contains("principal_identities"), org.mockito.ArgumentMatchers.<RowMapper<UUID>>any(),
      eq(ISSUER), eq(SUBJECT));
  }
}
