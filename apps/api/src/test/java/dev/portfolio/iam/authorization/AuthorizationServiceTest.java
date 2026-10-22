package dev.portfolio.iam.authorization;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static dev.portfolio.iam.authorization.AuthorizationResult.*;
import static dev.portfolio.iam.authorization.AuthorizationService.*;

class AuthorizationServiceTest {
  private static final UUID ALICE = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  private JdbcTemplate jdbc;
  private OpenFgaClient fga;
  private AuthorizationService service;

  @BeforeEach void setUp() {
    jdbc = mock(JdbcTemplate.class);
    fga = mock(OpenFgaClient.class);
    service = new AuthorizationService(jdbc, fga);
  }

  private void membership(String principal, String tenant, String membership) {
    when(jdbc.queryForList(MEMBERSHIP_SQL, ALICE, "acme")).thenReturn(List.of(Map.of(
      "principal_status", principal, "tenant_status", tenant, "membership_status", membership)));
  }

  private AuthorizationResult authorize() {
    return service.authorize(ALICE, "acme", ResourceType.PROJECT, "acme/roadmap", Permission.CAN_VIEW);
  }

  @ParameterizedTest @EnumSource(value = AuthorizationResult.class,
    names = {"ALLOW", "DENY", "TIMEOUT", "UNAVAILABLE", "INVALID_CONFIGURATION", "INVALID_RESPONSE"})
  void activeMembershipPropagatesDecisionOrFailure(AuthorizationResult result) {
    membership("ACTIVE", "ACTIVE", "ACTIVE");
    when(fga.check(ALICE, "project:acme/roadmap", "can_view")).thenReturn(result);
    assertEquals(result, authorize());
    var order = inOrder(jdbc, fga);
    order.verify(jdbc).queryForList(MEMBERSHIP_SQL, ALICE, "acme");
    order.verify(fga).check(ALICE, "project:acme/roadmap", "can_view");
  }

  @Test void missingMembershipDeniesWithoutOpenFga() {
    when(jdbc.queryForList(MEMBERSHIP_SQL, ALICE, "acme")).thenReturn(List.of());
    assertEquals(DENY, authorize());
    verifyNoInteractions(fga);
  }

  @ParameterizedTest @CsvSource({"DISABLED,ACTIVE,ACTIVE", "ACTIVE,SUSPENDED,ACTIVE",
    "ACTIVE,ACTIVE,DISABLED", "UNKNOWN,ACTIVE,ACTIVE"})
  void inactiveStateDeniesWithoutOpenFga(String principal, String tenant, String membership) {
    membership(principal, tenant, membership);
    assertEquals(DENY, authorize());
    verifyNoInteractions(fga);
  }

  @Test void databaseFailureFailsClosedWithoutOpenFga() {
    when(jdbc.queryForList(MEMBERSHIP_SQL, ALICE, "acme"))
      .thenThrow(new DataAccessResourceFailureException("unavailable"));
    assertEquals(DATABASE_FAILURE, authorize());
    verifyNoInteractions(fga);
  }

  @Test void wrongTenantCannotUseMembershipFromAnotherTenant() {
    when(jdbc.queryForList(MEMBERSHIP_SQL, ALICE, "globex")).thenReturn(List.of());
    assertEquals(DENY, service.authorize(ALICE, "globex", ResourceType.DOCUMENT,
      "globex/notes", Permission.CAN_EDIT));
    verify(jdbc).queryForList(MEMBERSHIP_SQL, ALICE, "globex");
    verifyNoInteractions(fga);
  }

  @ParameterizedTest @EnumSource(Permission.class)
  void mapsDocumentPermissions(Permission permission) {
    membership("ACTIVE", "ACTIVE", "ACTIVE");
    when(fga.check(ALICE, "document:acme/notes", permission.value)).thenReturn(ALLOW);
    assertEquals(ALLOW, service.authorize(ALICE, "acme", ResourceType.DOCUMENT,
      "acme/notes", permission));
  }

  @Test void invalidInputsNeverReachDependencies() {
    assertEquals(INVALID_REQUEST, service.authorize(null, "acme", ResourceType.PROJECT, "x", Permission.CAN_VIEW));
    assertEquals(INVALID_REQUEST, service.authorize(ALICE, "acme' OR 1=1", ResourceType.PROJECT, "x", Permission.CAN_VIEW));
    assertEquals(INVALID_REQUEST, service.authorize(ALICE, "acme", null, "x", Permission.CAN_VIEW));
    assertEquals(INVALID_REQUEST, service.authorize(ALICE, "acme", ResourceType.PROJECT, "x#owner", Permission.CAN_VIEW));
    assertEquals(INVALID_REQUEST, service.authorize(ALICE, "acme", ResourceType.PROJECT, "x", null));
    verifyNoInteractions(jdbc, fga);
  }

  @Test void onlyAllowGrantsAccess() {
    for (AuthorizationResult result : AuthorizationResult.values()) {
      assertEquals(result == ALLOW, result.isAllowed());
    }
  }
}
