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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.service.auth.PolarisCredentialFactory;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Test-only HTTP authentication mechanism that builds a {@link JsonWebToken}-backed {@link
 * SecurityIdentity} from a simple base64-encoded JSON bearer token. This bypasses the need to
 * create Polaris principals when running integration tests in external principal mode.
 */
@ApplicationScoped
class ExternalStubAuthenticationMechanism implements HttpAuthenticationMechanism {

  private static final Logger LOGGER =
      LoggerFactory.getLogger(ExternalStubAuthenticationMechanism.class);

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  @ConfigProperty(name = "polaris.test.external-auth.enabled", defaultValue = "false")
  boolean enabled;

  @Inject PolarisCredentialFactory credentialFactory;

  @Override
  public int getPriority() {
    return HttpAuthenticationMechanism.DEFAULT_PRIORITY;
  }

  @Override
  public Uni<SecurityIdentity> authenticate(
      RoutingContext context, IdentityProviderManager identityProviderManager) {

    if (!enabled) {
      return Uni.createFrom().nullItem();
    }

    String authHeader = context.request().getHeader("Authorization");
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      return Uni.createFrom().nullItem();
    }

    String token = authHeader.substring("Bearer ".length());
    Map<String, Object> claims = decodeClaims(token);
    if (claims.isEmpty()) {
      return Uni.createFrom().nullItem();
    }

    JsonWebToken jwt = new SimpleJsonWebToken(token, claims);
    Set<String> roles = extractRoles(claims);
    Long principalId = extractPrincipalId(claims.get("sub"));
    Object preferredUsername = claims.get("preferred_username");
    String principalName =
        preferredUsername != null
            ? preferredUsername.toString()
            : principalId != null ? principalId.toString() : null;

    PolarisPrincipal polarisPrincipal =
        PolarisPrincipal.of(
            principalName == null ? "unknown" : principalName,
            buildPrincipalProperties(principalId, principalName),
            roles == null ? Set.of() : roles);

    QuarkusSecurityIdentity.Builder builder =
        QuarkusSecurityIdentity.builder()
            .setPrincipal(polarisPrincipal)
            .addCredential(credentialFactory.create(principalId, principalName, roles))
            .addRoles(roles)
            .setAnonymous(false);

    // Make tenant id discoverable for the OIDC tenant resolver.
    Object tenant = claims.get("tenant");
    if (tenant != null) {
      builder.addAttribute(OidcUtils.TENANT_ID_ATTRIBUTE, tenant.toString());
    }

    return Uni.createFrom().item(builder.build());
  }

  @Override
  public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
    return Uni.createFrom()
        .item(new HttpCredentialTransport(HttpCredentialTransport.Type.AUTHORIZATION, "Bearer"));
  }

  @Override
  public Uni<ChallengeData> getChallenge(RoutingContext context) {
    return Uni.createFrom().nullItem();
  }

  @Override
  public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
    return Collections.emptySet();
  }

  private Map<String, Object> decodeClaims(String token) {
    try {
      byte[] json = Base64.getUrlDecoder().decode(token);
      return OBJECT_MAPPER.readValue(json, new TypeReference<>() {});
    } catch (Exception e) {
      LOGGER.warn("Failed to decode external test token", e);
      return Map.of();
    }
  }

  private Set<String> extractRoles(Map<String, Object> claims) {
    Object rolesClaim = claims.getOrDefault("roles", List.of());
    if (rolesClaim instanceof List<?> list) {
      return list.stream().map(Object::toString).collect(Collectors.toSet());
    }
    return Set.of();
  }

  private Map<String, String> buildPrincipalProperties(Long principalId, String principalName) {
    Map<String, String> props = new java.util.HashMap<>();
    if (principalId != null) {
      props.put("principal_id", principalId.toString());
    }
    if (principalName != null) {
      props.put("principal_name", principalName);
    }
    return props;
  }

  private Long extractPrincipalId(Object sub) {
    if (sub instanceof Number number) {
      return number.longValue();
    }
    if (sub != null) {
      try {
        return Long.parseLong(sub.toString());
      } catch (NumberFormatException ignored) {
      }
    }
    return null;
  }
}

/**
 * Minimal {@link JsonWebToken} implementation for tests. Claims are sourced directly from the
 * decoded token payload.
 */
class SimpleJsonWebToken implements JsonWebToken {

  private final String rawToken;
  private final Map<String, Object> claims;

  SimpleJsonWebToken(String rawToken, Map<String, Object> claims) {
    this.rawToken = rawToken;
    this.claims = claims;
  }

  @Override
  public String getName() {
    Object preferred = claims.get("preferred_username");
    if (preferred != null) {
      return preferred.toString();
    }
    Object sub = claims.get("sub");
    return sub == null ? null : sub.toString();
  }

  @Override
  public <T> T getClaim(String claimName) {
    @SuppressWarnings("unchecked")
    T value = (T) claims.get(claimName);
    return value;
  }

  @Override
  public Set<String> getClaimNames() {
    return claims.keySet();
  }

  @Override
  public String getRawToken() {
    return rawToken;
  }
}
