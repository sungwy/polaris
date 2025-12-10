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

import jakarta.annotation.PostConstruct;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import org.apache.polaris.service.auth.AuthenticationConfiguration;
import org.apache.polaris.service.auth.AuthenticationRealmConfiguration;
import org.apache.polaris.service.auth.AuthenticationType;

@Singleton
public class PrincipalModeConfigurationValidator {

  private final AuthorizationConfiguration authorizationConfiguration;
  private final AuthenticationConfiguration authenticationConfiguration;

  @Inject
  public PrincipalModeConfigurationValidator(
      AuthorizationConfiguration authorizationConfiguration,
      AuthenticationConfiguration authenticationConfiguration) {
    this.authorizationConfiguration = authorizationConfiguration;
    this.authenticationConfiguration = authenticationConfiguration;
  }

  @PostConstruct
  void validatePrincipalMode() {
    if (authorizationConfiguration.principalMode() != PrincipalMode.EXTERNAL) {
      return;
    }
    AuthenticationRealmConfiguration defaultRealm =
        authenticationConfiguration.forRealm(DEFAULT_REALM_KEY);
    if (defaultRealm.type() == AuthenticationType.INTERNAL) {
      throw new IllegalStateException(
          "Invalid configuration: polaris.authorization.principal-mode=external requires "
              + "polaris.authentication.type to be 'external' or 'mixed'.");
    }
  }
}
