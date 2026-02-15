-- Migration 018: Index usage analysis snapshots
-- Tracks index scan usage over time to help identify unused/low-value indexes.

CREATE TABLE IF NOT EXISTS index_stats (
    schemaname TEXT NOT NULL,
    relname TEXT NOT NULL,
    indexrelname TEXT NOT NULL,
    idx_scan BIGINT NOT NULL DEFAULT 0,
    idx_tup_read BIGINT NOT NULL DEFAULT 0,
    idx_tup_fetch BIGINT NOT NULL DEFAULT 0,
    index_size_bytes BIGINT NOT NULL DEFAULT 0,
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (schemaname, indexrelname)
);


CREATE OR REPLACE FUNCTION refresh_index_stats()
RETURNS VOID
LANGUAGE SQL
AS $$
    INSERT INTO index_stats (
        schemaname,
        relname,
        indexrelname,
        idx_scan,
        idx_tup_read,
        idx_tup_fetch,
        index_size_bytes,
        last_updated
    )
    SELECT
        s.schemaname,
        s.relname,
        s.indexrelname,
        s.idx_scan,
        s.idx_tup_read,
        s.idx_tup_fetch,
        pg_relation_size(s.indexrelid),
        now()
    FROM pg_stat_user_indexes s
    ON CONFLICT (schemaname, indexrelname)
    DO UPDATE SET
        relname = EXCLUDED.relname,
        idx_scan = EXCLUDED.idx_scan,
        idx_tup_read = EXCLUDED.idx_tup_read,
        idx_tup_fetch = EXCLUDED.idx_tup_fetch,
        index_size_bytes = EXCLUDED.index_size_bytes,
        last_updated = EXCLUDED.last_updated;
$$;


-- Materialize an initial snapshot at migration time.
SELECT refresh_index_stats();


CREATE OR REPLACE VIEW index_stats_unused AS
SELECT
    s.schemaname,
    s.relname,
    s.indexrelname,
    s.idx_scan,
    s.idx_tup_read,
    s.idx_tup_fetch,
    s.index_size_bytes,
    s.last_updated
FROM index_stats s
JOIN pg_class idx
    ON idx.relname = s.indexrelname
JOIN pg_namespace nsp
    ON nsp.oid = idx.relnamespace
    AND nsp.nspname = s.schemaname
JOIN pg_index pi
    ON pi.indexrelid = idx.oid
WHERE s.idx_scan = 0
  AND NOT pi.indisprimary;


INSERT INTO schema_migrations (version) VALUES ('018') ON CONFLICT (version) DO NOTHING;
