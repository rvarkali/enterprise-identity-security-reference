package dev.portfolio.iam.resources;

import java.sql.ResultSet;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.RowMapper;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class ResourceRepositoryTest {
  private static final UUID ID = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000003");
  private static final UUID TENANT = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000001");
  private static final UUID PARENT = UUID.fromString("aaaaaaaa-0000-4000-8000-000000000002");
  private JdbcTemplate jdbc;
  private ResourceRepository repository;
  private ResultSet row;

  @BeforeEach void setUp() throws Exception {
    jdbc = mock(JdbcTemplate.class);
    repository = new ResourceRepository(jdbc);
    row = mock(ResultSet.class);
    when(row.getObject("id", UUID.class)).thenReturn(ID);
    when(row.getObject("tenant_id", UUID.class)).thenReturn(TENANT);
    when(row.getObject("project_id", UUID.class)).thenReturn(PARENT);
    when(row.getString("slug")).thenReturn("acme");
    when(row.getString("name")).thenReturn("Resource name");
    when(row.getString("classification")).thenReturn("CONFIDENTIAL");
  }

  @Test void projectMapsDatabaseOwnershipAndBindsUuid() {
    when(jdbc.query(eq(ResourceRepository.PROJECT_SQL), any(RowMapper.class), eq(ID))).thenAnswer(call -> {
      RowMapper<?> mapper = call.getArgument(1);
      return List.of(mapper.mapRow(row, 0));
    });
    assertEquals(new ResourceRepository.Project(ID, TENANT, "acme", "Resource name"),
      repository.findProject(ID).orElseThrow());
    verify(jdbc).query(eq(ResourceRepository.PROJECT_SQL), any(RowMapper.class), eq(ID));
  }

  @Test void documentMapsDatabaseTenantAndParentAndBindsUuid() {
    when(jdbc.query(eq(ResourceRepository.DOCUMENT_SQL), any(RowMapper.class), eq(ID))).thenAnswer(call -> {
      RowMapper<?> mapper = call.getArgument(1);
      return List.of(mapper.mapRow(row, 0));
    });
    assertEquals(new ResourceRepository.Document(ID, TENANT, "acme", PARENT, "Resource name", "CONFIDENTIAL"),
      repository.findDocument(ID).orElseThrow());
    verify(jdbc).query(eq(ResourceRepository.DOCUMENT_SQL), any(RowMapper.class), eq(ID));
  }

  @Test void absentRowsAreEmpty() {
    assertTrue(repository.findProject(ID).isEmpty());
    assertTrue(repository.findDocument(ID).isEmpty());
  }

  @Test void membershipUsesPrincipalAndAuthoritativeTenantParameters() {
    when(jdbc.queryForObject(ResourceRepository.MEMBERSHIP_SQL, Boolean.class, ID, TENANT)).thenReturn(true);
    assertTrue(repository.hasMembership(ID, TENANT));
    assertFalse(repository.hasMembership(ID, PARENT));
    verify(jdbc).queryForObject(ResourceRepository.MEMBERSHIP_SQL, Boolean.class, ID, TENANT);
  }

  @Test void membershipSqlRequiresAllActiveStatesOnTheRequestedTenantAndPrincipal() {
    // Guard against removing a status predicate while mocked query results still pass.
    String sql = ResourceRepository.MEMBERSHIP_SQL;
    assertTrue(sql.contains("join principals p on p.id = tp.principal_id"));
    assertTrue(sql.contains("join tenants t on t.id = tp.tenant_id"));
    assertTrue(sql.contains("tp.principal_id = ? and tp.tenant_id = ?"));
    assertTrue(sql.contains("p.status = 'ACTIVE'"));
    assertTrue(sql.contains("t.status = 'ACTIVE'"));
    assertTrue(sql.contains("tp.status = 'ACTIVE'"));
  }

  @Test void missingOrInactiveEligibilityIsFalse() {
    when(jdbc.queryForObject(ResourceRepository.MEMBERSHIP_SQL, Boolean.class, ID, TENANT)).thenReturn(false);
    assertFalse(repository.hasMembership(ID, TENANT));
  }

  @Test void membershipDatabaseFailureIsNotConvertedToMissingMembership() {
    when(jdbc.queryForObject(ResourceRepository.MEMBERSHIP_SQL, Boolean.class, ID, TENANT))
      .thenThrow(new DataAccessResourceFailureException("unavailable"));
    assertThrows(DataAccessResourceFailureException.class, () -> repository.hasMembership(ID, TENANT));
  }

}
