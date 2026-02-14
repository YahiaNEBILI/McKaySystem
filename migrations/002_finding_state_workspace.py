from __future__ import annotations

"""
Backfill/migrate finding_state_current to be workspace-scoped.
"""


def _col_exists(cur, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    cur.execute(
        """
        SELECT EXISTS (
          SELECT 1
          FROM information_schema.columns
          WHERE table_schema = 'public'
            AND table_name = %s
            AND column_name = %s
        )
        """,
        (table, column),
    )
    row = cur.fetchone()
    return bool(row and row[0])


def _pk_name(cur, table: str) -> str | None:
    """Return the primary key constraint name for a table."""
    cur.execute(
        """
        SELECT constraint_name
        FROM information_schema.table_constraints
        WHERE table_schema='public'
          AND table_name=%s
          AND constraint_type='PRIMARY KEY'
        """,
        (table,),
    )
    row = cur.fetchone()
    return row[0] if row and row[0] else None


def upgrade(conn) -> None:
    """Upgrade migration: ensure workspace-scoped PK for finding_state_current."""
    with conn.cursor() as cur:
        if not _col_exists(cur, "finding_state_current", "workspace"):
            # Add nullable, backfill, then enforce NOT NULL to avoid long locks on large tables.
            cur.execute("ALTER TABLE finding_state_current ADD COLUMN workspace TEXT")
            cur.execute(
                "UPDATE finding_state_current SET workspace = 'default' WHERE workspace IS NULL"
            )
            cur.execute("ALTER TABLE finding_state_current ALTER COLUMN workspace SET NOT NULL")

        pk = _pk_name(cur, "finding_state_current")
        if pk:
            cur.execute(
                """
                SELECT COUNT(*) FROM information_schema.key_column_usage
                WHERE table_schema='public'
                  AND table_name='finding_state_current'
                  AND constraint_name=%s
                  AND column_name='workspace'
                """,
                (pk,),
            )
            row = cur.fetchone()
            has_ws = bool(row and row[0] and int(row[0]) > 0)
            if not has_ws:
                from psycopg2 import sql as pg_sql  # type: ignore

                cur.execute(
                    pg_sql.SQL("ALTER TABLE finding_state_current DROP CONSTRAINT {}").format(
                        pg_sql.Identifier(pk)
                    )
                )
                cur.execute(
                    "ALTER TABLE finding_state_current ADD PRIMARY KEY (tenant_id, workspace, fingerprint)"
                )
        else:
            cur.execute(
                "ALTER TABLE finding_state_current ADD PRIMARY KEY (tenant_id, workspace, fingerprint)"
            )

        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_finding_state_current_tenant_ws_state
              ON finding_state_current (tenant_id, workspace, state)
            """
        )

    conn.commit()
