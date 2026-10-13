-- The postgres image creates POSTGRES_USER (falx) as a SUPERUSER, and a superuser
-- bypasses row-level security — which would quietly disable the tenant isolation the
-- whole design rests on. Downgrade the application role to NOSUPERUSER NOBYPASSRLS as
-- soon as the database is initialised.
--
-- The role still owns the database and the public schema, so `fal-x migrate up` can
-- create the schema. FORCE row-level security (set by the migrations) keeps even the
-- owner subject to the tenant policies, so ownership does not reopen the hole.
ALTER ROLE falx NOSUPERUSER NOBYPASSRLS;
