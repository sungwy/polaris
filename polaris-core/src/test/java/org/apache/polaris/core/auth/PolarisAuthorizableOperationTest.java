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
package org.apache.polaris.core.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.apache.polaris.core.auth.PolarisAuthorizableOperation.PathEvaluationScope;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class PolarisAuthorizableOperationTest {

  @ParameterizedTest
  @EnumSource(PolarisAuthorizableOperation.class)
  void defaultOperandScopesUseRootAncestry(PolarisAuthorizableOperation operation) {
    if (operation == PolarisAuthorizableOperation.ATTACH_POLICY_TO_CATALOG
        || operation == PolarisAuthorizableOperation.ATTACH_POLICY_TO_NAMESPACE
        || operation == PolarisAuthorizableOperation.ATTACH_POLICY_TO_TABLE
        || operation == PolarisAuthorizableOperation.DETACH_POLICY_FROM_CATALOG
        || operation == PolarisAuthorizableOperation.DETACH_POLICY_FROM_NAMESPACE
        || operation == PolarisAuthorizableOperation.DETACH_POLICY_FROM_TABLE
        || operation == PolarisAuthorizableOperation.GET_APPLICABLE_POLICIES_ON_CATALOG) {
      return;
    }
    assertThat(operation.getTargetPathEvaluationScope()).isEqualTo(PathEvaluationScope.ROOT);
    assertThat(operation.getSecondaryPathEvaluationScope()).isEqualTo(PathEvaluationScope.ROOT);
  }

  @Test
  void policyMappingOperationsUseCatalogAncestryForBothOperands() {
    assertThat(PolarisAuthorizableOperation.ATTACH_POLICY_TO_CATALOG.getTargetPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_CATALOG.getSecondaryPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_NAMESPACE.getTargetPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_NAMESPACE
                .getSecondaryPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(PolarisAuthorizableOperation.ATTACH_POLICY_TO_TABLE.getTargetPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_TABLE.getSecondaryPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_CATALOG.getTargetPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_CATALOG
                .getSecondaryPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_NAMESPACE
                .getTargetPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_NAMESPACE
                .getSecondaryPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(PolarisAuthorizableOperation.DETACH_POLICY_FROM_TABLE.getTargetPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
    assertThat(
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_TABLE.getSecondaryPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
  }

  @Test
  void getApplicablePoliciesOnCatalogUsesCatalogAncestryForTarget() {
    assertThat(
            PolarisAuthorizableOperation.GET_APPLICABLE_POLICIES_ON_CATALOG
                .getTargetPathEvaluationScope())
        .isEqualTo(PathEvaluationScope.CATALOG);
  }

  @Test
  void catalogScopedTargetOperationsExactlyMatchLegacyHandlerMapping() {
    Set<PolarisAuthorizableOperation> expectedCatalogScopedTargets =
        Set.of(
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_CATALOG,
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_NAMESPACE,
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_TABLE,
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_CATALOG,
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_NAMESPACE,
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_TABLE,
            PolarisAuthorizableOperation.GET_APPLICABLE_POLICIES_ON_CATALOG);

    Set<PolarisAuthorizableOperation> actualCatalogScopedTargets =
        Arrays.stream(PolarisAuthorizableOperation.values())
            .filter(op -> op.getTargetPathEvaluationScope() == PathEvaluationScope.CATALOG)
            .collect(Collectors.toSet());

    assertThat(actualCatalogScopedTargets).isEqualTo(expectedCatalogScopedTargets);
  }

  @Test
  void catalogScopedSecondaryOperationsExactlyMatchLegacyHandlerMapping() {
    Set<PolarisAuthorizableOperation> expectedCatalogScopedSecondaries =
        Set.of(
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_CATALOG,
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_NAMESPACE,
            PolarisAuthorizableOperation.ATTACH_POLICY_TO_TABLE,
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_CATALOG,
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_NAMESPACE,
            PolarisAuthorizableOperation.DETACH_POLICY_FROM_TABLE);

    Set<PolarisAuthorizableOperation> actualCatalogScopedSecondaries =
        Arrays.stream(PolarisAuthorizableOperation.values())
            .filter(op -> op.getSecondaryPathEvaluationScope() == PathEvaluationScope.CATALOG)
            .collect(Collectors.toSet());

    assertThat(actualCatalogScopedSecondaries).isEqualTo(expectedCatalogScopedSecondaries);
  }
}
