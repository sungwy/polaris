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

import jakarta.annotation.Nullable;
import java.util.ArrayList;
import java.util.List;
import org.apache.polaris.core.entity.PolarisEntityType;

/**
 * Lexical path segment descriptor and helper functions for converting {@link PolarisSecurable}
 * intent into hierarchical segments.
 */
public record PathSegment(PolarisEntityType entityType, String name) {

  /**
   * Returns in-catalog path segments from securable name parts.
   *
   * <p>All segments except the last are namespaces. The last segment uses the securable type.
   */
  private static List<PathSegment> inCatalogSegments(PolarisSecurable securable) {
    List<String> nameParts = securable.getNameParts();
    if (nameParts.isEmpty()) {
      return List.of();
    }

    List<PathSegment> segments = new ArrayList<>(nameParts.size());
    for (int i = 0; i < nameParts.size(); i++) {
      PolarisEntityType segmentType =
          i == nameParts.size() - 1 ? securable.getEntityType() : PolarisEntityType.NAMESPACE;
      segments.add(new PathSegment(segmentType, nameParts.get(i)));
    }
    return segments;
  }

  /**
   * Returns lexical hierarchy segments for a securable, optionally prepending the reference
   * catalog.
   *
   * <p>For in-catalog entity types, the returned hierarchy is:
   *
   * <pre>
   *   [CATALOG(referenceCatalogName)] + inCatalogSegments(...)
   * </pre>
   *
   * <p>For top-level/non-catalog-scoped types (e.g. CATALOG, PRINCIPAL), the returned hierarchy is
   * just inCatalogSegments(...).
   */
  public static List<PathSegment> orderedParentToChildSegments(
      @Nullable String referenceCatalogName, PolarisSecurable securable) {
    List<PathSegment> inCatalog = inCatalogSegments(securable);
    if (!isCatalogScopedType(securable.getEntityType())
        || referenceCatalogName == null
        || referenceCatalogName.isBlank()) {
      return inCatalog;
    }

    List<PathSegment> full = new ArrayList<>(inCatalog.size() + 1);
    full.add(new PathSegment(PolarisEntityType.CATALOG, referenceCatalogName));
    full.addAll(inCatalog);
    return full;
  }

  private static boolean isCatalogScopedType(PolarisEntityType entityType) {
    PolarisEntityType current = entityType;
    while (current != null) {
      if (current == PolarisEntityType.CATALOG) {
        return true;
      }
      current = current.getParentType();
    }
    return false;
  }
}
