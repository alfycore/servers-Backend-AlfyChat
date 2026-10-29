// ==========================================
// ALFYCHAT - DATABASE CLIENT
// ==========================================

package platform

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"
)

// DB enveloppe le pool MySQL avec des helpers qui renvoient des lignes au
// même format que mysql2 (voir row.go).
type DB struct {
	*sql.DB
}

// OpenDatabase ouvre le pool avec les réglages des services TS
// (10 connexions, keepalive, connectTimeout 10 s, idleTimeout 60 s).
func OpenDatabase() (*DB, error) {
	return OpenDatabaseWithDefaults("alfychat", "alfychat")
}

// OpenDatabaseWithDefaults : identifiants par défaut propres au service
// quand DB_USER / DB_PASSWORD sont absents.
func OpenDatabaseWithDefaults(defUser, defPassword string) (*DB, error) {
	return OpenDatabaseSized(defUser, defPassword, 10)
}

// OpenDatabaseSized : comme OpenDatabaseWithDefaults avec une taille de pool.
func OpenDatabaseSized(defUser, defPassword string, poolSize int) (*DB, error) {
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", Env("DB_HOST", "localhost"), EnvInt("DB_PORT", 3306))
	cfg.User = Env("DB_USER", defUser)
	cfg.Passwd = Env("DB_PASSWORD", defPassword)
	cfg.DBName = Env("DB_NAME", "alfychat")
	// mysql2 lit les dates dans le fuseau du process (timezone: 'local').
	cfg.ParseTime = true
	// mysql2 active FOUND_ROWS par défaut : affectedRows compte les lignes trouvées, pas seulement modifiées.
	cfg.ClientFoundRows = true
	cfg.Loc = time.Local
	cfg.Timeout = 10 * time.Second
	cfg.Collation = "utf8mb4_unicode_ci"
	cfg.MultiStatements = false

	pool, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	pool.SetMaxOpenConns(poolSize)
	pool.SetMaxIdleConns(poolSize)
	pool.SetConnMaxIdleTime(60 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := pool.PingContext(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return &DB{pool}, nil
}

// Rows exécute une requête et renvoie toutes les lignes.
func (db *DB) Rows(ctx context.Context, query string, args ...any) ([]Row, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return ScanRows(rows)
}

// First renvoie la première ligne, ou nil s'il n'y en a aucune.
func (db *DB) First(ctx context.Context, query string, args ...any) (Row, error) {
	rows, err := db.Rows(ctx, query, args...)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// Exec exécute une écriture.
func (db *DB) Exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.ExecContext(ctx, query, args...)
}

// Placeholders renvoie "?,?,?" pour n paramètres.
func Placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, n*2-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}

// Args convertit une liste de chaînes en arguments de requête.
func Args(ids []string) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

// InTx exécute fn dans une transaction : validation si fn réussit, annulation sinon.
func (db *DB) InTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}
