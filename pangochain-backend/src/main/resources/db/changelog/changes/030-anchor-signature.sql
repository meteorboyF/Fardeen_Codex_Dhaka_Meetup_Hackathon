--liquibase formatted sql

-- Pre-submission audit finding S2: the reconciliation worker replayed whatever the
-- pending_anchor table contained, so an adversary with database write access could
-- forge or alter a pending mutation and have the worker submit it to the ledger with
-- the gateway's Fabric credentials. Rows are now authenticated with an HMAC computed
-- by the gateway over the replay-relevant fields, keyed by a secret held in gateway
-- configuration and never stored in the database. The worker refuses rows whose
-- signature does not verify, so a database writer can no longer mint ledger mutations
-- through the outbox; the residual surface is documented in the manuscript.

--changeset pangochain:030-anchor-signature
ALTER TABLE pending_anchor ADD COLUMN signature TEXT;
--rollback ALTER TABLE pending_anchor DROP COLUMN signature;
