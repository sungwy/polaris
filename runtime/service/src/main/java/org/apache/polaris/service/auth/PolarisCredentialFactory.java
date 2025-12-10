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

import jakarta.annotation.Nullable;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Set;
import org.apache.polaris.service.config.AuthorizationConfiguration;
import org.apache.polaris.service.config.PrincipalMode;

/**
 * Builds {@link PolarisCredential} instances while automatically tagging them with their origin
 * (internal vs external) according to the configured principal mode.
 */
@ApplicationScoped
public class PolarisCredentialFactory {

  private final AuthorizationConfiguration authorizationConfiguration;

  @Inject
  public PolarisCredentialFactory(AuthorizationConfiguration authorizationConfiguration) {
    this.authorizationConfiguration = authorizationConfiguration;
  }

  public PolarisCredential create(
      @Nullable Long principalId, @Nullable String principalName, Set<String> principalRoles) {
    boolean external = authorizationConfiguration.principalMode() == PrincipalMode.EXTERNAL;
    return ImmutablePolarisCredential.builder()
        .principalId(principalId)
        .principalName(principalName)
        .principalRoles(principalRoles)
        .external(external)
        .build();
  }
}
