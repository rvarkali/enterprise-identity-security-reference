package dev.portfolio.iam.authorization;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static dev.portfolio.iam.authorization.AuthorizationResult.*;

class OpenFgaClientTest {
  private static final String STORE = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
  private static final String MODEL = "01ARZ3NDEKTSV4RRFFQ69G5FAW";
  private static final UUID ALICE = UUID.fromString("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
  private HttpClient http;
  private ObjectMapper mapper;
  private OpenFgaProperties properties;
  private OpenFgaClient client;

  @BeforeEach void setUp() {
    http = mock(HttpClient.class);
    mapper = new ObjectMapper();
    properties = new OpenFgaProperties("http://localhost:8082/", STORE, MODEL,
      Duration.ofMillis(100), Duration.ofMillis(100));
    client = new OpenFgaClient(properties, mapper, http);
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
    return client.check(ALICE, "project:acme/roadmap", "can_view");
  }

  @Test void allowSendsInternalPrincipalAndPinnedModel() throws Exception {
    response(200, "{\"allowed\":true}");
    assertEquals(ALLOW, check());
    var request = ArgumentCaptor.forClass(HttpRequest.class);
    verify(http).sendAsync(request.capture(), any());
    assertEquals("http://localhost:8082/stores/" + STORE + "/check", request.getValue().uri().toString());
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
    assertEquals(MODEL, body.path("authorization_model_id").asText());
    assertEquals("user:" + ALICE, body.path("tuple_key").path("user").asText());
    assertEquals("project:acme/roadmap", body.path("tuple_key").path("object").asText());
    assertEquals("can_view", body.path("tuple_key").path("relation").asText());
    assertEquals("HIGHER_CONSISTENCY", body.path("consistency").asText());
    assertFalse(body.has("contextual_tuples"));
  }

  @Test void negativeDecisionIsNormalDeny() {
    response(200, "{\"allowed\":false}");
    assertEquals(DENY, check());
  }

  @ParameterizedTest @ValueSource(strings = {"", "null", "[]", "{}", "not-json",
    "{\"allowed\":null}", "{\"allowed\":\"true\"}", "{\"allowed\":1}",
    "{\"allowed\":true} {}", "{\"allowed\":false,\"allowed\":true}"})
  void malformedResponseFailsClosed(String body) {
    response(200, body);
    assertEquals(INVALID_RESPONSE, check());
  }

  @ParameterizedTest @ValueSource(ints = {301, 400, 401, 403, 404, 429, 500, 503})
  void nonSuccessIsDependencyFailureEvenWithAllowBody(int status) {
    response(status, "{\"allowed\":true}");
    assertEquals(UNAVAILABLE, check());
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
    assertTrue(output.getAll().contains("OpenFGA check failed: result=UNAVAILABLE"));
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
    for (OpenFgaProperties invalid : new OpenFgaProperties[] {
      new OpenFgaProperties("not a URI", STORE, MODEL, Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpenFgaProperties("file:///tmp/fga", STORE, MODEL, Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpenFgaProperties("http://user:secret@localhost", STORE, MODEL, Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpenFgaProperties("http://localhost?query=x", STORE, MODEL, Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpenFgaProperties(properties.apiUrl(), "", MODEL, Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpenFgaProperties(properties.apiUrl(), STORE, "", Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpenFgaProperties(properties.apiUrl(), "../bad", MODEL, Duration.ofSeconds(1), Duration.ofSeconds(2)),
      new OpenFgaProperties(properties.apiUrl(), STORE, MODEL, Duration.ZERO, Duration.ofSeconds(2)),
      new OpenFgaProperties(properties.apiUrl(), STORE, MODEL, Duration.ofSeconds(1), Duration.ofSeconds(31))
    }) {
      assertEquals(INVALID_CONFIGURATION,
        new OpenFgaClient(invalid, mapper, http).check(ALICE, "document:acme/notes", "can_edit"));
    }
    verifyNoInteractions(http);
  }

  @Test void springBindsExternalConfigurationAndCreatesClient() {
    new ApplicationContextRunner().withUserConfiguration(OpenFgaClient.class)
      .withBean(ObjectMapper.class, ObjectMapper::new)
      .withPropertyValues("iam.openfga.api-url=http://localhost:8082", "iam.openfga.store-id=" + STORE,
        "iam.openfga.authorization-model-id=" + MODEL, "iam.openfga.connect-timeout=100ms",
        "iam.openfga.request-timeout=2s")
      .run(context -> {
        assertNull(context.getStartupFailure());
        assertTrue(context.getBean(OpenFgaProperties.class).isValid());
        assertNotNull(context.getBean(OpenFgaClient.class));
      });
  }
}
