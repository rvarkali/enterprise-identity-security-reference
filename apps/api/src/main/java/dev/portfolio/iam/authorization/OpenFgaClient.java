package dev.portfolio.iam.authorization;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;
import static dev.portfolio.iam.authorization.AuthorizationResult.*;

@Component
@EnableConfigurationProperties(OpenFgaProperties.class)
public class OpenFgaClient {
  private static final Logger log = LoggerFactory.getLogger(OpenFgaClient.class);
  private final OpenFgaProperties properties;
  private final ObjectMapper mapper;
  private final HttpClient http;

  @Autowired
  public OpenFgaClient(OpenFgaProperties properties, ObjectMapper mapper) {
    this(properties, mapper, HttpClient.newBuilder()
      .connectTimeout(properties.isValid() ? properties.connectTimeout() : Duration.ofSeconds(1))
      .followRedirects(HttpClient.Redirect.NEVER).build());
  }

  OpenFgaClient(OpenFgaProperties properties, ObjectMapper mapper, HttpClient http) {
    this.properties = properties;
    this.mapper = mapper;
    this.http = http;
  }

  // Package-private: callers go through the PostgreSQL eligibility gate in AuthorizationService.
  AuthorizationResult check(UUID principal, String object, String permission) {
    if (!properties.isValid()) return INVALID_CONFIGURATION;
    CompletableFuture<HttpResponse<String>> pending = null;
    try {
      String body = mapper.writeValueAsString(Map.of(
        "authorization_model_id", properties.authorizationModelId(),
        "consistency", "HIGHER_CONSISTENCY",
        "tuple_key", Map.of("user", "user:" + principal, "object", object, "relation", permission)));
      String base = properties.apiUrl().replaceAll("/+$", "");
      HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/stores/" + properties.storeId() + "/check"))
        .timeout(properties.requestTimeout())
        .header("Content-Type", "application/json").header("Accept", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body)).build();
      try {
        pending = http.sendAsync(request, HttpResponse.BodyHandlers.ofString());
      } catch (RuntimeException e) {
        return dependencyFailure(UNAVAILABLE, e);
      }
      // Bounds the full response (including its body), not only connection/headers.
      HttpResponse<String> response = pending.get(properties.requestTimeout().toMillis(), TimeUnit.MILLISECONDS);
      if (response.statusCode() != 200) return UNAVAILABLE;
      JsonNode json = mapper.reader()
        .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
        .with(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY).readTree(response.body());
      if (json == null || !json.isObject() || !json.path("allowed").isBoolean()) return INVALID_RESPONSE;
      return json.get("allowed").booleanValue() ? ALLOW : DENY;
    } catch (JsonProcessingException e) {
      return INVALID_RESPONSE;
    } catch (TimeoutException e) {
      return TIMEOUT;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return UNAVAILABLE;
    } catch (ExecutionException e) {
      return dependencyFailure(e.getCause() instanceof HttpTimeoutException ? TIMEOUT : UNAVAILABLE, e.getCause());
    } catch (IllegalArgumentException e) {
      return INVALID_RESPONSE;
    } catch (RuntimeException e) {
      return dependencyFailure(UNAVAILABLE, e);
    } finally {
      if (pending != null && !pending.isDone()) pending.cancel(true);
    }
  }

  private AuthorizationResult dependencyFailure(AuthorizationResult result, Throwable failure) {
    // Exception messages, causes and stack traces may contain URLs, headers or response bodies.
    log.warn("OpenFGA check failed: result={}, exceptionType={}", result,
      failure == null ? "unknown" : failure.getClass().getName());
    return result;
  }
}
