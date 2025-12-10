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
package org.apache.polaris.service.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.Set;
import org.apache.iceberg.exceptions.NotAuthorizedException;
import org.apache.polaris.core.PolarisDiagnostics;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.context.CallContext;
import org.apache.polaris.core.persistence.PolarisMetaStoreManager;
import org.apache.polaris.service.config.AuthorizationConfiguration;
import org.apache.polaris.service.config.PrincipalMode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class DefaultAuthenticatorExternalModeTest {

  private DefaultAuthenticator authenticator;
  private PolarisMetaStoreManager metaStoreManager;

  @BeforeEach
  void setUp() {
    authenticator = new DefaultAuthenticator();
    metaStoreManager = mock(PolarisMetaStoreManager.class);
    authenticator.metaStoreManager = metaStoreManager;
    authenticator.callContext = mock(CallContext.class);
    authenticator.diagnostics = mock(PolarisDiagnostics.class);
    authenticator.authorizationConfiguration =
        new AuthorizationConfiguration() {
          @Override
          public String type() {
            return "internal";
          }

          @Override
          public PrincipalMode principalMode() {
            return PrincipalMode.EXTERNAL;
          }
        };
  }

  @Test
  void buildsPrincipalFromClaimsWithoutMetastore() {
    PolarisCredential credential =
        ImmutablePolarisCredential.builder()
            .principalId(42L)
            .principalName("external-user")
            .principalRoles(Set.of("roleA", "roleB"))
            .external(true)
            .build();

    PolarisPrincipal principal = authenticator.authenticate(credential);

    assertThat(principal.getName()).isEqualTo("external-user");
    assertThat(principal.getRoles()).containsExactlyInAnyOrder("roleA", "roleB");
    verifyNoInteractions(metaStoreManager);
  }

  @Test
  void usesPrincipalIdWhenNameMissing() {
    PolarisCredential credential =
        ImmutablePolarisCredential.builder()
            .principalId(99L)
            .principalRoles(Set.of())
            .external(true)
            .build();

    PolarisPrincipal principal = authenticator.authenticate(credential);

    assertThat(principal.getName()).isEqualTo("99");
    assertThat(principal.getRoles()).isEmpty();
    verifyNoInteractions(metaStoreManager);
  }

  @Test
  void rejectsMissingPrincipalIdentifiers() {
    PolarisCredential credential =
        ImmutablePolarisCredential.builder().principalRoles(Set.of("role")).external(true).build();

    assertThatThrownBy(() -> authenticator.authenticate(credential))
        .isInstanceOf(NotAuthorizedException.class);

    verifyNoInteractions(metaStoreManager);
  }
}
