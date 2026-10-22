package dev.portfolio.iam.resources;

import java.util.UUID;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class ResourceController {
  private final ResourceReadService resources;
  public ResourceController(ResourceReadService resources) { this.resources = resources; }

  @GetMapping("/projects/{projectId}")
  public ResourceRepository.Project project(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID projectId) {
    return resources.project(jwt, projectId);
  }

  @GetMapping("/documents/{documentId}")
  public ResourceRepository.Document document(@AuthenticationPrincipal Jwt jwt, @PathVariable UUID documentId) {
    return resources.document(jwt, documentId);
  }
}
