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
package org.apache.polaris.service.config;

import static org.apache.polaris.service.auth.AuthenticationConfiguration.DEFAULT_REALM_KEY;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.apache.polaris.service.auth.AuthenticationConfiguration;
import org.apache.polaris.service.auth.AuthenticationRealmConfiguration;
import org.apache.polaris.service.auth.AuthenticationType;
import org.junit.jupiter.api.Test;

class PrincipalModeConfigurationValidatorTest {

  @Test
  void rejectsExternalModeWithInternalAuthentication() {
    AuthenticationRealmConfiguration realmConfig = mock(AuthenticationRealmConfiguration.class);
    when(realmConfig.type()).thenReturn(AuthenticationType.INTERNAL);
    AuthenticationConfiguration authenticationConfiguration =
        new TestAuthenticationConfiguration(realmConfig);
    AuthorizationConfiguration authorizationConfiguration =
        new TestAuthorizationConfiguration(PrincipalMode.EXTERNAL);

    PrincipalModeConfigurationValidator validator =
        new PrincipalModeConfigurationValidator(
            authorizationConfiguration, authenticationConfiguration);

    assertThatThrownBy(validator::validatePrincipalMode)
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("polaris.authorization.principal-mode=external");
  }

  @Test
  void acceptsCompatibleModes() {
    AuthenticationRealmConfiguration realmConfig = mock(AuthenticationRealmConfiguration.class);
    when(realmConfig.type()).thenReturn(AuthenticationType.MIXED);
    AuthenticationConfiguration authenticationConfiguration =
        new TestAuthenticationConfiguration(realmConfig);
    AuthorizationConfiguration authorizationConfiguration =
        new TestAuthorizationConfiguration(PrincipalMode.EXTERNAL);

    PrincipalModeConfigurationValidator validator =
        new PrincipalModeConfigurationValidator(
            authorizationConfiguration, authenticationConfiguration);

    assertThatCode(validator::validatePrincipalMode).doesNotThrowAnyException();
  }

  private static final class TestAuthorizationConfiguration implements AuthorizationConfiguration {

    private final PrincipalMode mode;

    private TestAuthorizationConfiguration(PrincipalMode mode) {
      this.mode = mode;
    }

    @Override
    public String type() {
      return "internal";
    }

    @Override
    public PrincipalMode principalMode() {
      return mode;
    }
  }

  private static final class TestAuthenticationConfiguration
      implements AuthenticationConfiguration {

    private final AuthenticationRealmConfiguration realmConfig;

    private TestAuthenticationConfiguration(AuthenticationRealmConfiguration realmConfig) {
      this.realmConfig = realmConfig;
    }

    @Override
    public Map<String, AuthenticationRealmConfiguration> realms() {
      return Map.of(DEFAULT_REALM_KEY, realmConfig);
    }
  }
}
