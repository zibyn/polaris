-- +goose Up

-- OIDC Back-Channel Logout (ADR 0022, docs/spec/protocol.md#back-channel-logout).
-- Only a Web (confidential) Application has a back end to tell.
ALTER TABLE applications ADD COLUMN backchannel_logout_uri text,
    ADD CONSTRAINT applications_backchannel_logout_check CHECK (backchannel_logout_uri IS NULL OR type = 'confidential');

-- The Applications a Session issued tokens to, kept as long as the Session:
-- a grant may be gone long before (code flow without a refresh token).
CREATE TABLE session_applications (
    session_id text NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    client_id  text NOT NULL REFERENCES applications (client_id) ON DELETE CASCADE,
    PRIMARY KEY (session_id, client_id)
);
CREATE INDEX ON session_applications (client_id);

-- A delivery is a webhook event, or a logout token (payload: sub, sid) that
-- the sender signs when it goes out.
ALTER TABLE webhook_deliveries ADD COLUMN kind text NOT NULL DEFAULT 'webhook'
    CHECK (kind IN ('webhook', 'logout'));

-- Ending a Session queues a logout token for each Application it issued
-- tokens to that wants one, whichever query ends it: setting ended_at, or
-- deleting a live Session (its User is deleted). A lapsed Session sends
-- nothing; nobody ended it. BEFORE DELETE: the cascade has not yet taken
-- its session_applications.
-- +goose StatementBegin
CREATE FUNCTION queue_logout_tokens() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO webhook_deliveries (client_id, kind, payload)
    SELECT a.client_id, 'logout', jsonb_build_object('sub', OLD.user_id, 'sid', OLD.id)
    FROM session_applications sa JOIN applications a USING (client_id)
    WHERE sa.session_id = OLD.id AND a.backchannel_logout_uri IS NOT NULL;
    RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END
$$;
-- +goose StatementEnd
CREATE TRIGGER queue_logout_tokens_on_end AFTER UPDATE OF ended_at ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND NEW.ended_at IS NOT NULL)
    EXECUTE FUNCTION queue_logout_tokens();
CREATE TRIGGER queue_logout_tokens_on_delete BEFORE DELETE ON sessions
    FOR EACH ROW WHEN (OLD.ended_at IS NULL AND OLD.last_seen_at + OLD.idle_timeout > now())
    EXECUTE FUNCTION queue_logout_tokens();

-- +goose Down

DROP TRIGGER queue_logout_tokens_on_delete ON sessions;
DROP TRIGGER queue_logout_tokens_on_end ON sessions;
DROP FUNCTION queue_logout_tokens();
DELETE FROM webhook_deliveries WHERE kind = 'logout';
ALTER TABLE webhook_deliveries DROP COLUMN kind;
DROP TABLE session_applications;
ALTER TABLE applications DROP CONSTRAINT applications_backchannel_logout_check,
    DROP COLUMN backchannel_logout_uri;
