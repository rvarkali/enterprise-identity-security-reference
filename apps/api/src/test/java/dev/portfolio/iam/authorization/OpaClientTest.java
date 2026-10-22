package dev.portfolio.iam.authorization;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullSource;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static dev.portfolio.iam.authorization.AuthorizationResult.*;

class OpaClientTest {
  private HttpClient http;
  private ObjectMapper mapper;
  private OpaProperties properties;
  private OpaClient client;

  @BeforeEach void setUp() {
    http = mock(HttpClient.class);
    mapper = new ObjectMapper();
    properties = new OpaProperties("http://localhost:8181/", Duration.ofMillis(100), Duration.ofMillis(100));
    client = new OpaClient(properties, mapper, http);
  }

  @SuppressWarnings("unchecked")
  private void response(int status, String body) {
    HttpResponse<String> response = mock(HttpResponse.class);
    when(response.statusCode()).thenReturn(status);
    when(response.body()).thenReturn(body);
    when(http.sendAsync(any(HttpRequest.class), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
      .thenReturn(CompletableFuture.completedFuture(response));
  }

  private AuthorizationResult check() {
    return client.checkRead(AuthorizationService.ResourceType.PROJECT, null);
  }

  @ParameterizedTest @NullSource @ValueSource(strings = {"PUBLIC", "INTERNAL", "CONFIDENTIAL"})
  void sendsBackendInputWithoutAssurance(String classification) throws Exception {
    response(200, "{\"result\":true}");
    var type = classification == null ? AuthorizationService.ResourceType.PROJECT : AuthorizationService.ResourceType.DOCUMENT;
    assertEquals(ALLOW, client.checkRead(type, classification));
    var request = ArgumentCaptor.forClass(HttpRequest.class);
    verify(http).sendAsync(request.capture(), any());
    assertEquals("http://localhost:8181/v1/data/iam/access/allow", request.getValue().uri().toString());
    assertEquals("POST", request.getValue().method());
    assertEquals(properties.requestTimeout(), request.getValue().timeout().orElseThrow());
    assertEquals("application/json", request.getValue().headers().firstValue("Content-Type").orElseThrow());
    var bodyBytes = new java.io.ByteArrayOutputStream();
    var completed = new CompletableFuture<Void>();
    request.getValue().bodyPublisher().orElseThrow().subscribe(new java.util.concurrent.Flow.Subscriber<java.nio.ByteBuffer>() {
      public void onSubscribe(java.util.concurrent.Flow.Subscription subscription) { subscription.request(Long.MAX_VALUE); }
      public void onNext(java.nio.ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.remaining()]; buffer.get(bytes); bodyBytes.writeBytes(bytes);
      }
      public void onError(Throwable error) { completed.completeExceptionally(error); }
      public void onComplete() { completed.complete(null); }
    });
    completed.get();
    var body = mapper.readTree(bodyBytes.toString(StandardCharsets.UTF_8));
    var expected = mapper.readTree("""
      {"input":{"resource_type":"project","action":"can_view","openfga_allowed":true,"authentication":{}}}
      """);
    if (classification != null) {
      var input = (com.fasterxml.jackson.databind.node.ObjectNode) expected.get("input");
      input.put("resource_type", "document");
      input.put("classification", classification);
    }
    assertEquals(expected, body);
  }

  @Test void negativeDecisionIsNormalDeny() {
    response(200, "{\"result\":false}");
    assertEquals(DENY, check());
  }

  @ParameterizedTest @ValueSource(strings = {"", "null", "[]", "{}", "not-json", "true", "42", "\"text\"",
    "{\"result\":null}", "{\"result\":\"true\"}", "{\"result\":1}", "{\"result\":{\"allow\":true}}", "{\"result\":[]}",
    "{\"result\":true} {}", "{\"result\":true} garbage", "{\"result\":true} false",
    "{\"result\":false,\"result\":true}", "{\"result\":true,\"result\":true}",
    "{\"result\":true,\"metrics\":{\"count\":1,\"count\":2}}",
    "{\"decision_id\":\"test-decision\"}", "{\"result\":true"})
  void malformedResponseFailsClosed(String body) {
    response(200, body);
    assertEquals(INVALID_RESPONSE, check());
  }

  @ParameterizedTest @ValueSource(ints = {201, 204, 206, 301, 400, 401, 403, 404, 429, 500, 503})
  void nonSuccessIsDependencyFailureEvenWithAllowBody(int status) {
    response(status, "{\"result\":true}");
    assertEquals(UNAVAILABLE, check());
  }

  @ParameterizedTest @ValueSource(booleans = {true, false})
  void optionalMetadataDoesNotChangeBooleanDecision(boolean allowed) {
    response(200, """
      {"decision_id":"04789f85-de5a-477b-8aa5-6d59d7742135",
       "result":%s,"metrics":{"timer_rego_query_eval_ns":123}}
      """.formatted(allowed));
    assertEquals(allowed ? ALLOW : DENY, check());
  }

  @ParameterizedTest @ValueSource(strings = {
    "http://opa:8181", "http://opa:8181/", "https://opa.example.test/proxy/"})
  void baseUrlAppendsDecisionPath(String baseUrl) {
    response(200, "{\"result\":true}");
    var configured = new OpaProperties(baseUrl, properties.connectTimeout(), properties.requestTimeout());
    assertTrue(configured.isValid());
    assertEquals(ALLOW, new OpaClient(configured, mapper, http)
      .checkRead(AuthorizationService.ResourceType.PROJECT, null));
    var request = ArgumentCaptor.forClass(HttpRequest.class);
    verify(http).sendAsync(request.capture(), any());
    assertEquals(baseUrl.replaceAll("/+$", "") + "/v1/data/iam/access/allow",
      request.getValue().uri().toString());
  }

  @ParameterizedTest @NullSource @ValueSource(strings = {
    "", "/relative", "http://", "http://opa:0", "http://opa:65536", "http://opa:8181/#fragment"})
  void invalidBaseUrlNeverSendsRequest(String baseUrl) {
    var invalid = new OpaProperties(baseUrl, properties.connectTimeout(), properties.requestTimeout());
    assertEquals(INVALID_CONFIGURATION, new OpaClient(invalid, mapper, http)
      .checkRead(AuthorizationService.ResourceType.PROJECT, null));
    verifyNoInteractions(http);
  }

  @Test void unavailableFailsClosed() {
    when(http.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
      .thenReturn(CompletableFuture.failedFuture(new IOException("connection refused")));
    assertEquals(UNAVAILABLE, check());
  }

  @Test
  @ExtendWith(OutputCaptureExtension.class)
  void unexpectedHttpRuntimeFailuresAreSanitizedDependencyFailures(CapturedOutput output) {
    String sensitiveMessage = "Bearer test-secret-token https://user:password@example.test";
    for (RuntimeException failure : new RuntimeException[] {
      new IllegalStateException(sensitiveMessage),
      new IllegalArgumentException(sensitiveMessage),
      new java.util.concurrent.RejectedExecutionException(sensitiveMessage)
    }) {
      reset(http);
      when(http.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
        .thenThrow(failure);
      AuthorizationResult result = check();
      assertEquals(UNAVAILABLE, result);
      assertFalse(result.isAllowed());
      assertTrue(output.getAll().contains(failure.getClass().getName()));
    }
    assertTrue(output.getAll().contains("OPA check failed: result=UNAVAILABLE"));
    assertFalse(output.getAll().contains(sensitiveMessage));
    assertFalse(output.getAll().contains("test-secret-token"));
    assertFalse(output.getAll().contains("user:password"));
  }

  @Test void asynchronousRuntimeFailureFailsClosed() {
    when(http.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
      .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("unexpected")));
    assertEquals(UNAVAILABLE, check());
  }

  @Test void httpTimeoutFailsClosed() {
    when(http.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any()))
      .thenReturn(CompletableFuture.failedFuture(new HttpTimeoutException("timeout")));
    assertEquals(TIMEOUT, check());
  }

  @Test void fullResponseDeadlineCancelsPendingRequest() {
    var pending = new CompletableFuture<HttpResponse<String>>();
    when(http.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenReturn(pending);
    assertTimeoutPreemptively(Duration.ofSeconds(2), () -> assertEquals(TIMEOUT, check()));
    assertTrue(pending.isCancelled());
  }

  @Test void interruptedCallPreservesInterruptAndDenies() {
    var pending = new CompletableFuture<HttpResponse<String>>();
    when(http.sendAsync(any(), org.mockito.ArgumentMatchers.<HttpResponse.BodyHandler<String>>any())).thenReturn(pending);
    try {
      Thread.currentThread().interrupt();
      assertEquals(UNAVAILABLE, check());
      assertTrue(Thread.currentThread().isInterrupted());
      assertTrue(pending.isCancelled());
    } finally {
      Thread.interrupted();
    }
  }

  @Test void invalidConfigurationDoesNotSendRequest() {
    for (OpaProperties invalid : new OpaProperties[] {
      new OpaProperties("not a URI", Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpaProperties("file:///tmp/opa", Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpaProperties("http://user:secret@localhost", Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpaProperties("http://localhost?query=x", Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpaProperties(properties.apiUrl(), Duration.ZERO, Duration.ofSeconds(2)),
      new OpaProperties(properties.apiUrl(), Duration.ofSeconds(1), Duration.ofSeconds(31))
    }) {
      assertEquals(INVALID_CONFIGURATION,
        new OpaClient(invalid, mapper, http).checkRead(AuthorizationService.ResourceType.DOCUMENT, "INTERNAL"));
    }
    verifyNoInteractions(http);
  }

  @Test void springBindsExternalConfigurationAndCreatesClient() {
    new ApplicationContextRunner().withUserConfiguration(OpaClient.class)
      .withBean(ObjectMapper.class, ObjectMapper::new)
      .withPropertyValues("iam.opa.api-url=http://localhost:8181", "iam.opa.connect-timeout=100ms",
        "iam.opa.request-timeout=2s")
      .run(context -> {
        assertNull(context.getStartupFailure());
        assertTrue(context.getBean(OpaProperties.class).isValid());
        assertNotNull(context.getBean(OpaClient.class));
      });
  }
}
