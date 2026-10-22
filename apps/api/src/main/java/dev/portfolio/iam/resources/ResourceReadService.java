package dev.portfolio.iam.resources;

import dev.portfolio.iam.PrincipalResolver;
import dev.portfolio.iam.authorization.AuthorizationResult;
import dev.portfolio.iam.authorization.AuthorizationService;
import dev.portfolio.iam.authorization.OpaClient;
import java.util.UUID;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import static dev.portfolio.iam.authorization.AuthorizationService.Permission.CAN_VIEW;
import static dev.portfolio.iam.authorization.AuthorizationService.ResourceType.*;

@Service
public class ResourceReadService {
  private final ResourceRepository resources;
  private final PrincipalResolver principals;
  private final AuthorizationService authorization;
  private final OpaClient opa;

  public ResourceReadService(ResourceRepository resources, PrincipalResolver principals,
                             AuthorizationService authorization, OpaClient opa) {
    this.resources = resources;
    this.principals = principals;
    this.authorization = authorization;
    this.opa = opa;
  }

  public ResourceRepository.Project project(Jwt jwt, UUID id) {
    var event = new SecurityEvent("project");
    try {
      UUID principal = principals.resolve(jwt);
      event.principal = principal; event.reason = "RESOURCE_OR_ELIGIBILITY";
      var project = resources.findProject(id).orElseThrow(ResourceReadService::notFound);
      requireView(principal, project.tenantId(), project.tenantSlug(), PROJECT, project.id(), event);
      event.reason = "OPA_DENY";
      requireContext(PROJECT, null);
      event.allow(project.tenantId(), project.id());
      return project;
    } catch (DataAccessException e) {
      event.failure();
      throw unavailable();
    } catch (ResponseStatusException e) {
      if (e.getStatusCode().value() == 503) event.failure();
      throw e;
    } catch (RuntimeException e) {
      event.failure();
      throw e;
    } finally { event.emit(); }
  }

  public ResourceRepository.Document document(Jwt jwt, UUID id) {
    var event = new SecurityEvent("document");
    try {
      UUID principal = principals.resolve(jwt);
      event.principal = principal; event.reason = "RESOURCE_OR_ELIGIBILITY";
      var document = resources.findDocument(id).orElseThrow(ResourceReadService::notFound);
      requireView(principal, document.tenantId(), document.tenantSlug(), DOCUMENT, document.id(), event);
      event.reason = "OPA_DENY";
      requireContext(DOCUMENT, document.classification());
      event.allow(document.tenantId(), document.id());
      return document;
    } catch (DataAccessException e) {
      event.failure();
      throw unavailable();
    } catch (ResponseStatusException e) {
      if (e.getStatusCode().value() == 503) event.failure();
      throw e;
    } catch (RuntimeException e) {
      event.failure();
      throw e;
    } finally { event.emit(); }
  }

  private void requireView(UUID principal, UUID tenantId, String tenantSlug,
                           AuthorizationService.ResourceType type, UUID resourceId, SecurityEvent event) {
    if (!resources.hasMembership(principal, tenantId)) throw notFound();
    AuthorizationResult result = authorization.authorize(principal, tenantSlug, type, resourceId.toString(), CAN_VIEW);
    if (result == AuthorizationResult.ALLOW) return;
    if (result == AuthorizationResult.DENY) {
      // Eligibility may have been revoked since the initial concealment check.
      if (!resources.hasMembership(principal, tenantId)) throw notFound();
      event.reason = "RELATIONSHIP_OR_ELIGIBILITY_DENY";
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Resource access denied");
    }
    // Includes configuration, malformed responses and unexpected/null results. Never expose details.
    throw unavailable();
  }

  private void requireContext(AuthorizationService.ResourceType type, String classification) {
    AuthorizationResult result = opa.checkRead(type, classification);
    if (result == AuthorizationResult.ALLOW) return;
    if (result == AuthorizationResult.DENY) {
      throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Resource access denied");
    }
    throw unavailable();
  }

  // One event per service invocation. No caller-controlled strings or exception details.
  private static final class SecurityEvent {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger("security.authorization");
    final UUID correlation = UUID.randomUUID();
    final String type;
    UUID principal, tenant, resource;
    String outcome = "DENY", reason = "IDENTITY_INELIGIBLE";
    SecurityEvent(String type) { this.type = type; }
    void allow(UUID tenant, UUID resource) {
      this.tenant = tenant; this.resource = resource; outcome = "ALLOW"; reason = "ALL_GATES_PASSED";
    }
    void failure() { outcome = "ERROR"; reason = "DEPENDENCY_OR_INTERNAL_FAILURE"; }
    void emit() {
      LOG.info("event_type=RESOURCE_AUTHORIZATION timestamp={} correlation_id={} principal_id={} tenant_id={} resource_type={} resource_id={} action=can_view outcome={} reason={}",
        java.time.Instant.now(), correlation, principal, tenant, type, resource, outcome, reason);
    }
  }

  private static ResponseStatusException notFound() {
    return new ResponseStatusException(HttpStatus.NOT_FOUND, "Resource not found");
  }

  private static ResponseStatusException unavailable() {
    return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Authorization dependency unavailable");
  }
}
