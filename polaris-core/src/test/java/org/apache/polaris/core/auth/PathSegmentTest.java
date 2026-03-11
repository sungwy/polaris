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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.apache.polaris.core.entity.PolarisEntityType;
import org.junit.jupiter.api.Test;

public class PathSegmentTest {

  @Test
  void orderedParentToChildSegmentsPrependsReferenceCatalogForCatalogScopedTypes() {
    PolarisSecurable table =
        PolarisSecurable.of(PolarisEntityType.TABLE_LIKE, List.of("ns1", "table1"));

    List<PathSegment> segments = PathSegment.orderedParentToChildSegments("catalogA", table);

    assertThat(segments).hasSize(3);
    assertThat(segments.get(0).entityType()).isEqualTo(PolarisEntityType.CATALOG);
    assertThat(segments.get(0).name()).isEqualTo("catalogA");
    assertThat(segments.get(1).entityType()).isEqualTo(PolarisEntityType.NAMESPACE);
    assertThat(segments.get(1).name()).isEqualTo("ns1");
    assertThat(segments.get(2).entityType()).isEqualTo(PolarisEntityType.TABLE_LIKE);
    assertThat(segments.get(2).name()).isEqualTo("table1");
  }

  @Test
  void orderedParentToChildSegmentsDoesNotPrependCatalogForNonCatalogScopedSecurable() {
    PolarisSecurable principal =
        PolarisSecurable.of(PolarisEntityType.PRINCIPAL, List.of("principalA"));

    List<PathSegment> segments = PathSegment.orderedParentToChildSegments("ignored", principal);

    assertThat(segments).hasSize(1);
    assertThat(segments.get(0).entityType()).isEqualTo(PolarisEntityType.PRINCIPAL);
    assertThat(segments.get(0).name()).isEqualTo("principalA");
  }

  @Test
  void orderedParentToChildSegmentsDoesNotPrependCatalogForCatalogLeaf() {
    PolarisSecurable catalog = PolarisSecurable.of(PolarisEntityType.CATALOG, List.of("catalogA"));

    List<PathSegment> segments = PathSegment.orderedParentToChildSegments("catalogA", catalog);

    assertThat(segments).hasSize(1);
    assertThat(segments.get(0).entityType()).isEqualTo(PolarisEntityType.CATALOG);
    assertThat(segments.get(0).name()).isEqualTo("catalogA");
  }

  @Test
  void orderedParentToChildSegmentsThrowsWhenCatalogScopedAndReferenceCatalogMissing() {
    PolarisSecurable table =
        PolarisSecurable.of(PolarisEntityType.TABLE_LIKE, List.of("ns1", "table1"));

    assertThatThrownBy(() -> PathSegment.orderedParentToChildSegments(null, table))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("referenceCatalogName must be non-empty");
    assertThatThrownBy(() -> PathSegment.orderedParentToChildSegments("  ", table))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("referenceCatalogName must be non-empty");
  }

  @Test
  void orderedParentToChildSegmentsAllowsMissingReferenceCatalogForNonCatalogScopedSecurable() {
    PolarisSecurable principal =
        PolarisSecurable.of(PolarisEntityType.PRINCIPAL, List.of("principalA"));

    List<PathSegment> segments = PathSegment.orderedParentToChildSegments(null, principal);

    assertThat(segments).hasSize(1);
    assertThat(segments.get(0).entityType()).isEqualTo(PolarisEntityType.PRINCIPAL);
    assertThat(segments.get(0).name()).isEqualTo("principalA");
  }
}
