package people

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/BhargavPalan/Fal-X/internal/graph"
	"github.com/BhargavPalan/Fal-X/internal/storetest"
)

func TestPeopleDerivesContactsAndFormat(t *testing.T) {
	db := storetest.NewTestDB(t)
	ctx := context.Background()
	slug := fmt.Sprintf("people-%d", time.Now().UnixNano())
	orgID, err := db.EnsureOrg(ctx, slug, slug)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.SQL().ExecContext(ctx, "DELETE FROM org WHERE slug = $1", slug) })

	scoped, _ := db.WithOrg(ctx, orgID)

	// Seed one estate domain and a handful of harvested emails: two personal addresses
	// on the estate domain, a role inbox, and a personal address on a third-party domain.
	emails := []string{"jane.doe@acme.com", "john.doe@acme.com", "info@acme.com", "bob.smith@gmail.com"}
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		if _, err := graph.Resolve(ctx, tx, orgID, graph.TypeDomain, "acme.com", "acme.com", 0); err != nil {
			return err
		}
		for _, a := range emails {
			if _, err := graph.Resolve(ctx, tx, orgID, graph.TypeEmail, a, a, 1); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := Run(ctx, scoped, orgID); err != nil {
		t.Fatal(err)
	}

	// The two personal estate addresses and the third-party personal address become
	// contacts; the role inbox does not.
	var persons []string
	var format, infoKind string
	var hasEmailEdges int
	// readPersons reads and closes its result set before the scalar queries below run
	// on the same transaction, so the connection is free for them.
	readPersons := func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT key FROM entity WHERE type = 'person' ORDER BY key")
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return err
			}
			persons = append(persons, k)
		}
		return rows.Err()
	}
	if err := scoped.InTx(ctx, func(tx *sql.Tx) error {
		if err := readPersons(tx); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT f.value FROM entity_fact f JOIN entity e ON e.id = f.entity_id
			WHERE e.type = 'domain' AND e.key = 'acme.com' AND f.key = 'email_format'`).Scan(&format); err != nil {
			return fmt.Errorf("read email_format: %w", err)
		}
		if err := tx.QueryRowContext(ctx, `
			SELECT f.value FROM entity_fact f JOIN entity e ON e.id = f.entity_id
			WHERE e.type = 'email' AND e.key = 'info@acme.com' AND f.key = 'address_kind'`).Scan(&infoKind); err != nil {
			return fmt.Errorf("read info address_kind: %w", err)
		}
		return tx.QueryRowContext(ctx,
			"SELECT count(*) FROM entity_edge WHERE rel = 'has_email'").Scan(&hasEmailEdges)
	}); err != nil {
		t.Fatal(err)
	}

	want := []string{"bob smith", "jane doe", "john doe"}
	sort.Strings(persons)
	if strings.Join(persons, ",") != strings.Join(want, ",") {
		t.Errorf("persons = %v, want %v (role inbox info@ must not become a person)", persons, want)
	}
	if format != "{first}.{last}" {
		t.Errorf("acme.com email_format = %q, want {first}.{last}", format)
	}
	if infoKind != "role" {
		t.Errorf("info@acme.com address_kind = %q, want role", infoKind)
	}
	if hasEmailEdges != 3 {
		t.Errorf("has_email edges = %d, want 3", hasEmailEdges)
	}
}
