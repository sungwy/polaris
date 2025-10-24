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

package org.apache.polaris.extension.auth.opa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.entity.PolarisBaseEntity;
import org.apache.polaris.core.entity.PolarisEntity;
import org.apache.polaris.core.entity.PolarisEntityType;
import org.apache.polaris.core.persistence.PolarisResolvedPathWrapper;
import org.apache.polaris.core.persistence.ResolvedPolarisEntity;
import org.apache.polaris.extension.auth.opa.token.StaticBearerTokenProvider;
import org.apache.polaris.nosql.async.java.JavaPoolAsyncExec;
import org.assertj.core.api.ThrowingConsumer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;

public class OpaAuthorizerIT {
  private static OpaContainer container;
  private static JavaPoolAsyncExec asyncExec;
  private static CloseableHttpClient httpClient;

  final AtomicReference<ObjectNode> lastInput = new AtomicReference<>();
  final AtomicReference<ObjectNode> lastResponse = new AtomicReference<>();

  @BeforeAll
  static void startOpa() {
    container = new OpaContainer().start();
    httpClient = HttpClients.custom().build();
    asyncExec = new JavaPoolAsyncExec();
  }

  @AfterAll
  static void stopOpa() throws Exception {
    try {
      container.close();
    } finally {
      try {
        httpClient.close();
      } finally {
        asyncExec.close();
      }
    }
  }

  void withPolicy(
      TestInfo testInfo, String regoPolicy, ThrowingConsumer<OpaPolarisAuthorizer> withAuthorizer) {
    lastInput.set(null);
    lastResponse.set(null);

    String name = testInfo.getTestMethod().orElseThrow().getName();
    URI policyUri = container.loadRegoPolicy(name, regoPolicy);

    // Extend OpaPolarisAuthorizer to capture request and response
    OpaPolarisAuthorizer authorizer =
        new OpaPolarisAuthorizer(
            policyUri,
            httpClient,
            new ObjectMapper(),
            new StaticBearerTokenProvider("static-token")) {
          @Override
          ObjectNode buildOpaInputJson(
              PolarisPrincipal principal,
              Set<PolarisBaseEntity> entities,
              PolarisAuthorizableOperation op,
              List<PolarisResolvedPathWrapper> targets,
              List<PolarisResolvedPathWrapper> secondaries)
              throws IOException {
            var input = super.buildOpaInputJson(principal, entities, op, targets, secondaries);
            lastInput.set(input);
            return input;
          }

          @Override
          ObjectNode parseResponse(HttpEntity entity) {
            ObjectNode response = super.parseResponse(entity);
            lastResponse.set(response);
            return response;
          }
        };

    withAuthorizer.accept(authorizer);
  }

  @Test
  public void aliceLoadTable(TestInfo testInfo) {
    // Set up a realistic principal
    PolarisPrincipal principal =
        PolarisPrincipal.of(
            "alice",
            Map.of("department", "analytics", "level", "senior"),
            Set.of("data_engineer", "analyst"));

    // Create a hierarchical resource structure: catalog.namespace.table
    // Create catalog entity using builder pattern
    PolarisEntity catalogEntity =
        new PolarisEntity.Builder()
            .setName("prod_catalog")
            .setType(PolarisEntityType.CATALOG)
            .setId(100L)
            .setCatalogId(100L)
            .setParentId(0L)
            .setCreateTimestamp(System.currentTimeMillis())
            .build();

    // Create namespace entity using builder pattern
    PolarisEntity namespaceEntity =
        new PolarisEntity.Builder()
            .setName("sales_data")
            .setType(PolarisEntityType.NAMESPACE)
            .setId(200L)
            .setCatalogId(100L)
            .setParentId(100L)
            .setCreateTimestamp(System.currentTimeMillis())
            .build();

    // Create table entity using builder pattern
    PolarisEntity tableEntity =
        new PolarisEntity.Builder()
            .setName("customer_orders")
            .setType(PolarisEntityType.TABLE_LIKE)
            .setId(300L)
            .setCatalogId(100L)
            .setParentId(200L)
            .setCreateTimestamp(System.currentTimeMillis())
            .build();

    // Create hierarchical path: catalog -> namespace -> table
    // Build a realistic resolved path using ResolvedPolarisEntity objects
    List<ResolvedPolarisEntity> resolvedPath =
        List.of(
            createResolvedEntity(catalogEntity),
            createResolvedEntity(namespaceEntity),
            createResolvedEntity(tableEntity));
    PolarisResolvedPathWrapper tablePath = new PolarisResolvedPathWrapper(resolvedPath);

    Set<PolarisBaseEntity> entities = Set.of(catalogEntity, namespaceEntity, tableEntity);

    withPolicy(
        testInfo,
        """
        default allow := false

        allow {
          input.actor.principal == "alice"
        }
        """,
        authorizer -> {
          assertThatNoException()
              .isThrownBy(
                  () ->
                      authorizer.authorizeOrThrow(
                          principal,
                          entities,
                          PolarisAuthorizableOperation.LOAD_TABLE,
                          tablePath,
                          null));

          // Captured request
          var root = lastInput.get();

          // Verify top-level structure
          assertThat(root.has("input")).as("Root should have 'input' field").isTrue();
          var input = root.get("input");
          assertThat(input.has("actor")).as("Input should have 'actor' field").isTrue();
          assertThat(input.has("action")).as("Input should have 'action' field").isTrue();
          assertThat(input.has("resource")).as("Input should have 'resource' field").isTrue();
          assertThat(input.has("context")).as("Input should have 'context' field").isTrue();

          // Verify actor details
          var actor = input.get("actor");
          assertThat(actor.has("principal")).as("Actor should have 'principal' field").isTrue();
          assertThat(actor.get("principal").asText()).isEqualTo("alice");
          assertThat(actor.has("roles")).as("Actor should have 'roles' field").isTrue();
          assertThat(actor.get("roles").isArray()).as("Roles should be an array").isTrue();
          assertThat(actor.get("roles").size()).isEqualTo(2);

          // Verify action
          var action = input.get("action");
          assertThat(action.asText()).isEqualTo("LOAD_TABLE");

          // Verify resource structure - this is the key part for hierarchical resources
          var resource = input.get("resource");
          assertThat(resource.has("targets")).as("Resource should have 'targets' field").isTrue();
          assertThat(resource.has("secondaries"))
              .as("Resource should have 'secondaries' field")
              .isTrue();

          var targets = resource.get("targets");
          assertThat(targets.isArray()).as("Targets should be an array").isTrue();
          assertThat(targets.size()).as("Should have exactly one target").isEqualTo(1);

          var target = targets.get(0);
          // Verify the target entity (table) details
          assertThat(target.isObject()).as("Target should be an object").isTrue();
          assertThat(target.has("type")).as("Target should have 'type' field").isTrue();
          assertThat(target.get("type").asText())
              .as("Target type should be TABLE_LIKE")
              .isEqualTo("TABLE_LIKE");
          assertThat(target.has("name")).as("Target should have 'name' field").isTrue();
          assertThat(target.get("name").asText())
              .as("Target name should be customer_orders")
              .isEqualTo("customer_orders");

          // Verify the hierarchical parents array
          assertThat(target.has("parents")).as("Target should have 'parents' field").isTrue();
          var parents = target.get("parents");
          assertThat(parents.isArray()).as("Parents should be an array").isTrue();
          assertThat(parents.size())
              .as("Should have 2 parents (catalog and namespace)")
              .isEqualTo(2);

          // Verify catalog parent (first in the hierarchy)
          var catalogParent = parents.get(0);
          assertThat(catalogParent.get("type").asText())
              .as("First parent should be catalog")
              .isEqualTo("CATALOG");
          assertThat(catalogParent.get("name").asText())
              .as("Catalog name should be prod_catalog")
              .isEqualTo("prod_catalog");

          // Verify namespace parent (second in the hierarchy)
          var namespaceParent = parents.get(1);
          assertThat(namespaceParent.get("type").asText())
              .as("Second parent should be namespace")
              .isEqualTo("NAMESPACE");
          assertThat(namespaceParent.get("name").asText())
              .as("Namespace name should be sales_data")
              .isEqualTo("sales_data");

          var secondaries = resource.get("secondaries");
          assertThat(secondaries.isArray()).as("Secondaries should be an array").isTrue();
          assertThat(secondaries.size()).as("Should have no secondaries in this test").isEqualTo(0);

          // Captured response
          var response = lastResponse.get();
          assertThat(response.has("result")).as("Response should have 'result' field").isTrue();
          var result = response.get("result");
          assertThat(result.has("allow")).as("Response should have 'allow' field").isTrue();
          assertThat(result.get("allow").asBoolean()).as("Result should be true").isTrue();
        });
  }

  private ResolvedPolarisEntity createResolvedEntity(PolarisEntity entity) {
    return new ResolvedPolarisEntity(entity, List.of(), List.of());
  }
}
