CREATE TABLE IF NOT EXISTS reports (
  sha        TEXT PRIMARY KEY,
  verdict    TEXT NOT NULL,
  score      INTEGER NOT NULL DEFAULT 0,
  count      INTEGER NOT NULL DEFAULT 1,
  rules      TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reports_last_seen ON reports(last_seen DESC);
