/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.polaris.extension.auth.opa.test;

import static io.restassured.RestAssured.given;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.QuarkusTestProfile.TestResourceEntry;
import io.quarkus.test.junit.TestProfile;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.DockerClientFactory;

/**
 * Integration test exercising OPA authorization when Polaris runs in external principal mode. The
 * authentication step is backed by a test-only authentication mechanism that builds JWT-based
 * identities from a simple bearer token, bypassing principal creation in Polaris.
 */
@QuarkusTest
@TestProfile(OpaExternalPrincipalIntegrationTest.ExternalOpaProfile.class)
public class OpaExternalPrincipalIntegrationTest extends OpaIntegrationTestBase {

  @BeforeAll
  static void requireDocker() {
    try {
      DockerClientFactory.instance().client();
    } catch (Throwable t) {
      Assumptions.assumeTrue(false, "Docker not available: " + t.getMessage());
    }
  }

  /**
   * Configures Polaris for external principal mode with the OPA authorizer and enables the
   * test-only authentication mechanism that accepts base64-encoded JSON bearer tokens.
   */
  public static class ExternalOpaProfile implements QuarkusTestProfile {
    @Override
    public Map<String, String> getConfigOverrides() {
      Map<String, String> config = new HashMap<>();
      config.put("polaris.authorization.type", "opa");
      config.put("polaris.authorization.principal-mode", "external");
      config.put("polaris.authentication.type", "external");
      config.put("polaris.test.external-auth.enabled", "true");

      // Configure OPA bearer auth
      config.put("polaris.authorization.opa.auth.type", "bearer");
      config.put(
          "polaris.authorization.opa.auth.bearer.static-token.value",
          "test-opa-bearer-token-12345");

      // Disable Quarkus OIDC devservice; the test-only auth mechanism supplies the identity
      config.put("quarkus.oidc.enabled", "false");

      // Map JWT claims to Polaris principal fields
      config.put("polaris.oidc.principal-mapper.id-claim-path", "sub");
      config.put("polaris.oidc.principal-mapper.name-claim-path", "preferred_username");
      config.put("polaris.oidc.principal-roles-mapper.filter", ".*");
      return config;
    }

    @Override
    public List<TestResourceEntry> testResources() {
      return List.of(new TestResourceEntry(OpaTestResource.class));
    }
  }

  @Test
  void testOpaAllowsRootUserExternalMode() {
    String token = createExternalToken("external-root-id", "root");

    given()
        .header("Authorization", "Bearer " + token)
        .when()
        .get("api/management/v1/catalogs")
        .then()
        .statusCode(200);
  }

  @Test
  void testOpaAllowsAdminUserExternalMode() {
    String token = createExternalToken("external-admin-id", "admin");

    given()
        .header("Authorization", "Bearer " + token)
        .when()
        .get("api/management/v1/catalogs")
        .then()
        .statusCode(200);
  }

  @Test
  void testOpaPolicyDeniesStrangerUserExternalMode() {
    String token = createExternalToken("external-stranger-id", "stranger");

    given()
        .header("Authorization", "Bearer " + token)
        .when()
        .get("api/management/v1/catalogs")
        .then()
        .statusCode(403);
  }

  private static String createExternalToken(String subject, String preferredUsername) {
    Map<String, Object> claims = new HashMap<>();
    claims.put("sub", subject);
    claims.put("preferred_username", preferredUsername);
    // Roles are optional for these policy checks but present to exercise role mapping
    claims.put("roles", List.of("PRINCIPAL_ROLE:ALL"));
    try {
      byte[] json = new ObjectMapper().writeValueAsBytes(claims);
      return Base64.getUrlEncoder().withoutPadding().encodeToString(json);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("Failed to encode external token", e);
    }
  }
}
