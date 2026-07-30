package systems.hugmesh.gateway.cache;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.lang.Nullable;

import java.time.Instant;
import java.util.UUID;

/**
 * One row of the {@code gateway_route_access} SOURCE OF TRUTH (Postgres) —
 * the relational (Spring Data R2DBC) entity the gateway reads its own
 * gateway's access rules from. Replaces the former raw
 * {@code DatabaseClient} SQL mapping in
 * {@link GatewayRouteAccessService#loadFromPostgres()}.
 *
 * <p>Columns / types mirror {@code compose/route-access-seed.sql} (and the
 * canonical {@code cluster/manifests/route-access/schema.sql}) EXACTLY:
 * <pre>
 *   id           uuid PRIMARY KEY DEFAULT gen_random_uuid()
 *   gateway      text        NOT NULL
 *   url_pattern  text        NOT NULL
 *   role         text        NOT NULL
 *   casdoor_user text
 *   allow        boolean     NOT NULL DEFAULT true
 *   domain       text
 *   mfa_required boolean     NOT NULL DEFAULT false
 *   updated_at   timestamptz NOT NULL DEFAULT now()
 * </pre>
 *
 * <p>This entity carries the full column set the gateway SELECT touches.
 * {@code id} is a {@code uuid}; the legacy query cast it {@code id::text AS id}
 * to flatten it into the {@link GatewayRouteAccessService.Rule} string field, so
 * the service mapper now calls {@code UUID#toString()} for byte-identical
 * behaviour. Records stay records — this is a relational record entity.
 */
@Table("gateway_route_access")
public record GatewayRouteAccessRow(
        @Id
        @Column("id")
        @Nullable UUID id,
        @Column("gateway")
        String gateway,
        @Column("url_pattern")
        String urlPattern,
        @Column("role")
        String role,
        @Column("casdoor_user")
        @Nullable String casdoorUser,
        @Column("allow")
        boolean allow,
        @Column("domain")
        @Nullable String domain,
        @Column("mfa_required")
        boolean mfaRequired,
        @Column("updated_at")
        @Nullable Instant updatedAt) {
}
