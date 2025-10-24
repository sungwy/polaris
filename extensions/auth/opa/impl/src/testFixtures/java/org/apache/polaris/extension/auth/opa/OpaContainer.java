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

import static java.util.Objects.requireNonNull;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.apache.polaris.containerspec.ContainerSpecHelper;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

public class OpaContainer implements AutoCloseable {
  private GenericContainer<?> opaContainer;
  private URI baseUri;

  public OpaContainer() {
    opaContainer =
        new GenericContainer<>(
                ContainerSpecHelper.containerSpecHelper("opa", OpaContainer.class)
                    .dockerImageName(null))
            .withExposedPorts(8181)
            .withReuse(true)
            .withCommand("run", "--server", "--addr=0.0.0.0:8181")
            .withLogConsumer(new Slf4jLogConsumer(LoggerFactory.getLogger(OpaContainer.class)))
            .waitingFor(
                Wait.forHttp("/health")
                    .forPort(8181)
                    .forStatusCode(200)
                    .withStartupTimeout(Duration.ofSeconds(120)));
  }

  public GenericContainer<?> getContainer() {
    return opaContainer;
  }

  public OpaContainer start() {
    opaContainer.start();

    int mappedPort = requireNonNull(opaContainer, "OpaContainer not started").getMappedPort(8181);
    String containerHost = opaContainer.getHost();
    baseUri = URI.create("http://" + containerHost + ":" + mappedPort);

    return this;
  }

  public URI baseUri() {
    return requireNonNull(baseUri, "OpaContainer not started");
  }

  /**
   * Load a policy into OPA.
   *
   * @param policyName name of the policy. The package name will be {@code
   *     polaris.test.{policyName}} and prefixed to {@code regoPolicy}.
   * @param regoPolicy OPA policy content
   * @return Policy URI
   */
  public URI loadRegoPolicy(String policyName, String regoPolicy) {
    try {
      String packageName = "polaris.test." + policyName;
      regoPolicy = "package " + packageName + "\n" + regoPolicy;

      URI baseUri = baseUri();
      URI updloadUri = baseUri.resolve("/v1/policies/" + policyName);
      System.out.println("Uploading policy to: " + updloadUri);

      HttpURLConnection conn = (HttpURLConnection) updloadUri.toURL().openConnection();
      conn.setRequestMethod("PUT");
      conn.setDoOutput(true);
      conn.setRequestProperty("Content-Type", "text/plain");

      try (OutputStream os = conn.getOutputStream()) {
        os.write(regoPolicy.getBytes(StandardCharsets.UTF_8));
      }

      int code = conn.getResponseCode();
      System.out.println("OPA policy upload response code: " + code);

      if (code < 200 || code >= 300) {
        throw new RuntimeException("OPA policy upload failed, HTTP " + code);
      }

      System.out.println("Successfully uploaded policy to OPA");

      return baseUri.resolve("/v1/data/polaris/test/" + policyName);
    } catch (Exception e) {
      // Surface container logs to help debug on CI
      throw new RuntimeException("Failed to load OPA policy.", e);
    }
  }

  @Override
  public void close() {
    var container = opaContainer;
    try {
      if (container != null) {
        container.close();
      }
    } finally {
      opaContainer = null;
    }
  }
}
