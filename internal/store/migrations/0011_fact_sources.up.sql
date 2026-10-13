-- Record the distinct set of sources that have asserted each fact, so confidence can
-- reflect corroboration: a value seen by several independent sources is far more
-- trustworthy than one seen by a single source, the cheapest false-positive filter in
-- recon. The scalar `source` column is kept as the most recent asserter for display.
BEGIN;

ALTER TABLE entity_fact ADD COLUMN sources text[] NOT NULL DEFAULT '{}';

-- Seed the set from the source already recorded on existing rows.
UPDATE entity_fact SET sources = ARRAY[source] WHERE source <> '' AND cardinality(sources) = 0;

COMMIT;
