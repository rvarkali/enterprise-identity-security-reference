package dev.portfolio.iam.machine;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/** Authenticated machine API liveness only; does not assert OPA/OpenFGA availability. */
@RestController
public class MachinePolicyController {
  @RequestMapping(value = "/api/machine/policy/health", method = {
      RequestMethod.GET, RequestMethod.HEAD, RequestMethod.OPTIONS, RequestMethod.TRACE,
      RequestMethod.POST, RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE})
  public ResponseEntity<Map<String, String>> health(HttpServletRequest request) {
    // Explicitly exclude implicit HEAD/OPTIONS handling as well as write methods.
    if (!"GET".equals(request.getMethod())) {
      return ResponseEntity.status(405).header(HttpHeaders.ALLOW, "GET").build();
    }
    return ResponseEntity.ok().header(HttpHeaders.CACHE_CONTROL, "no-store")
        .body(Map.of("status", "UP"));
  }
}
