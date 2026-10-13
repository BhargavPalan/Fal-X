-- Rollback of 0009_graph.up.sql.

BEGIN;

DROP TABLE IF EXISTS source_cache;
DROP TABLE IF EXISTS entity_fact;
DROP TABLE IF EXISTS entity_edge;
DROP TABLE IF EXISTS entity;

COMMIT;
