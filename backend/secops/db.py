"""Small DB-API unit of work. PostgreSQL in deployment; SQLite only in hermetic tests."""
import contextlib
import pathlib
import sqlite3


class Transaction:
    def __init__(self, conn, postgres):
        self.conn, self.postgres = conn, postgres

    def execute(self, sql, args=()):
        return self.conn.execute(sql.replace("?", "%s") if self.postgres else sql, args)

    def one(self, sql, args=()):
        row = self.execute(sql, args).fetchone()
        return dict(row) if row is not None else None

    def all(self, sql, args=()):
        return [dict(r) for r in self.execute(sql, args).fetchall()]

    def lock_org(self, org):
        self.execute("SELECT id FROM organizations WHERE id=?" + (" FOR UPDATE" if self.postgres else ""), (org,))


class Database:
    def __init__(self, url):
        self.url = url
        self.postgres = not url.startswith("sqlite:///")

    def connect(self):
        if self.postgres:
            import psycopg
            from psycopg.rows import dict_row
            return psycopg.connect(self.url, row_factory=dict_row, connect_timeout=5)
        conn = sqlite3.connect(self.url.removeprefix("sqlite:///"), timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @contextlib.contextmanager
    def transaction(self):
        conn = self.connect()
        try:
            if not self.postgres:
                conn.execute("BEGIN IMMEDIATE")
            yield Transaction(conn, self.postgres)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def migrate(self):
        root = pathlib.Path(__file__).parent.parent / "migrations"
        with self.transaction() as tx:
            tx.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)")
            if tx.postgres:
                tx.execute("SELECT pg_advisory_xact_lock(6712941)")
            for path in sorted(root.glob("[0-9]*.sql")):
                if tx.one("SELECT version FROM schema_migrations WHERE version=?", (path.name,)):
                    continue
                for statement in path.read_text(encoding="utf-8").split(";\n"):
                    if statement.strip():
                        tx.execute(statement)
                tx.execute("INSERT INTO schema_migrations VALUES (?)", (path.name,))
            if tx.postgres:
                # Audit records cannot be changed by application SQL, even accidentally.
                tx.execute("""CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger
                LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit is append only'; END $$""")
                tx.execute("DROP TRIGGER IF EXISTS audit_immutable ON audit")
                tx.execute("CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation()")
            else:
                for operation in ("UPDATE", "DELETE"):
                    tx.execute(f"CREATE TRIGGER IF NOT EXISTS audit_no_{operation} BEFORE {operation} ON audit BEGIN SELECT RAISE(ABORT, 'audit is append only'); END")
