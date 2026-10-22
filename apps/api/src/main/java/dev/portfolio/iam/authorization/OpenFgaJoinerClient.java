package dev.portfolio.iam.authorization;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import static dev.portfolio.iam.authorization.AuthorizationResult.*;

/** Read-only inventory for disabled joiners. No tuple mutation capability. */
@Component
@EnableConfigurationProperties(OpenFgaProperties.class)
public class OpenFgaJoinerClient {
  public enum Membership { ABSENT, CONFLICT }
  public static final class Failure extends RuntimeException {
    private final AuthorizationResult result;
    public Failure(AuthorizationResult result) { super("OpenFGA provisioning dependency failure: " + result); this.result = result; }
    public AuthorizationResult result() { return result; }
  }
  private final OpenFgaProperties properties;
  private final ObjectMapper mapper;
  private final HttpClient http;

  @Autowired
  public OpenFgaJoinerClient(OpenFgaProperties properties, ObjectMapper mapper) {
    this(properties, mapper, HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
      .connectTimeout(properties.isValid() ? properties.connectTimeout() : Duration.ofSeconds(1)).build());
  }
  OpenFgaJoinerClient(OpenFgaProperties properties, ObjectMapper mapper, HttpClient http) {
    this.properties = properties; this.mapper = mapper; this.http = http;
  }

  // Inspect all direct relationships for this disabled principal in the current model's types.
  // Other principals' tuples are neither returned by the filter nor modified.
  public Membership read(UUID principal, String slug) {
    var expected = tuple(principal, slug);
    for (String type : List.of("tenant", "project", "document")) {
      String token = "";
      Set<String> seen = new HashSet<>();
      for (int page = 0; ; page++) {
        if (page >= 10) throw new Failure(INVALID_RESPONSE); // Bounded inventory; never accept a truncated scan.
        JsonNode body = call("read", Map.of("tuple_key", Map.of("user", expected.get("user"), "object", type + ":"),
          "page_size", 100, "continuation_token", token, "consistency", "HIGHER_CONSISTENCY"));
        if (!body.path("tuples").isArray()) throw new Failure(INVALID_RESPONSE);
        for (JsonNode row : body.get("tuples")) {
          JsonNode key = row.path("key");
          if (!key.isObject() || !key.path("user").isTextual() || !key.path("relation").isTextual()
              || !key.path("object").isTextual() || !key.get("user").asText().equals(expected.get("user"))
              || !key.get("object").asText().startsWith(type + ":")) throw new Failure(INVALID_RESPONSE);
          return Membership.CONFLICT; // Any direct relationship is premature for this new disabled joiner.
        }
        JsonNode next = body.get("continuation_token");
        if (next == null) token = "";
        else if (next.isTextual()) token = next.asText();
        else throw new Failure(INVALID_RESPONSE);
        if (token.isEmpty()) break;
        if (!seen.add(token)) throw new Failure(INVALID_RESPONSE);
      }
    }
    return Membership.ABSENT;
  }

  private Map<String, String> tuple(UUID principal, String slug) {
    if (principal == null || slug == null || !slug.matches("[a-z0-9][a-z0-9-]{0,62}")) throw new Failure(INVALID_REQUEST);
    return Map.of("user", "user:" + principal, "relation", "member", "object", "tenant:" + slug);
  }

  private JsonNode call(String operation, Map<String, ?> payload) {
    if (!properties.isValid()) throw new Failure(INVALID_CONFIGURATION);
    CompletableFuture<HttpResponse<String>> pending = null;
    try {
      var request = HttpRequest.newBuilder(URI.create(properties.apiUrl().replaceAll("/+$", "")
          + "/stores/" + properties.storeId() + "/" + operation))
        .timeout(properties.requestTimeout()).header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(payload))).build();
      pending = http.sendAsync(request, HttpResponse.BodyHandlers.ofString());
      var response = pending.get(properties.requestTimeout().toMillis(), TimeUnit.MILLISECONDS);
      if (response.statusCode() != 200) throw new Failure(response.statusCode() == 400 ? INVALID_REQUEST : UNAVAILABLE);
      JsonNode json = mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .with(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY).readTree(response.body());
      if (json == null || !json.isObject()) throw new Failure(INVALID_RESPONSE);
      return json;
    } catch (Failure e) { throw e;
    } catch (com.fasterxml.jackson.core.JsonProcessingException e) { throw new Failure(INVALID_RESPONSE);
    } catch (TimeoutException e) { throw new Failure(TIMEOUT);
    } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new Failure(UNAVAILABLE);
    } catch (ExecutionException e) { throw new Failure(e.getCause() instanceof HttpTimeoutException ? TIMEOUT : UNAVAILABLE);
    } catch (RuntimeException e) { throw new Failure(UNAVAILABLE);
    } finally { if (pending != null && !pending.isDone()) pending.cancel(true); }
  }
}
