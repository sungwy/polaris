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

import java.util.Set;
import org.apache.polaris.service.config.AuthorizationConfiguration;
import org.apache.polaris.service.config.PrincipalMode;
import org.junit.jupiter.api.Test;

class PolarisCredentialFactoryTest {

  @Test
  void createsInternalCredentialsByDefault() {
    PolarisCredentialFactory factory =
        new PolarisCredentialFactory(new StubAuthorizationConfiguration(PrincipalMode.INTERNAL));

    PolarisCredential credential = factory.create(123L, "alice", Set.of("role"));

    assertThat(credential.isExternal()).isFalse();
  }

  @Test
  void createsExternalCredentialsWhenConfigured() {
    PolarisCredentialFactory factory =
        new PolarisCredentialFactory(new StubAuthorizationConfiguration(PrincipalMode.EXTERNAL));

    PolarisCredential credential = factory.create(null, "bob", Set.of());

    assertThat(credential.isExternal()).isTrue();
  }

  private static final class StubAuthorizationConfiguration implements AuthorizationConfiguration {

    private final PrincipalMode principalMode;

    private StubAuthorizationConfiguration(PrincipalMode principalMode) {
      this.principalMode = principalMode;
    }

    @Override
    public String type() {
      return "internal";
    }

    @Override
    public PrincipalMode principalMode() {
      return principalMode;
    }
  }
}
