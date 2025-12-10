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

package org.apache.polaris.core.persistence.resolver;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.apache.polaris.core.PolarisDiagnostics;
import org.apache.polaris.core.auth.PolarisPrincipal;
import org.apache.polaris.core.context.RealmContext;

public class ResolutionManifestFactoryImpl implements ResolutionManifestFactory {

  private final PolarisDiagnostics diagnostics;
  private final RealmContext realmContext;
  private final ResolverFactory resolverFactory;
  private final boolean useCallerPrincipalFromContext;

  /**
   * @deprecated Use {@link #ResolutionManifestFactoryImpl(PolarisDiagnostics, RealmContext,
   *     ResolverFactory, boolean)} to explicitly control caller-principal resolution behavior.
   */
  @Deprecated
  public ResolutionManifestFactoryImpl(
      @Nonnull PolarisDiagnostics diagnostics,
      @Nonnull RealmContext realmContext,
      @Nonnull ResolverFactory resolverFactory,
      boolean useCallerPrincipalFromContext) {
    this.diagnostics = diagnostics;
    this.realmContext = realmContext;
    this.resolverFactory = resolverFactory;
    this.useCallerPrincipalFromContext = useCallerPrincipalFromContext;
  }

  /**
   * @deprecated Use {@link #ResolutionManifestFactoryImpl(PolarisDiagnostics, RealmContext,
   *     ResolverFactory, boolean)}.
   */
  @Deprecated
  public ResolutionManifestFactoryImpl(
      @Nonnull PolarisDiagnostics diagnostics,
      @Nonnull RealmContext realmContext,
      @Nonnull ResolverFactory resolverFactory) {
    this(diagnostics, realmContext, resolverFactory, false);
  }

  @Nonnull
  @Override
  public PolarisResolutionManifest createResolutionManifest(
      @Nonnull PolarisPrincipal principal, @Nullable String referenceCatalogName) {
    return createResolutionManifest(principal, referenceCatalogName, useCallerPrincipalFromContext);
  }

  @Nonnull
  @Override
  public PolarisResolutionManifest createResolutionManifest(
      @Nonnull PolarisPrincipal principal,
      @Nullable String referenceCatalogName,
      boolean useCallerPrincipalFromContext) {
    return new PolarisResolutionManifest(
        diagnostics,
        realmContext,
        resolverFactory,
        principal,
        referenceCatalogName,
        useCallerPrincipalFromContext);
  }
}
