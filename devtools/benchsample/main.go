// Command benchsample lists version-boundary candidates for the matcher benchmark.
//
// For one CPE product it prints, per CVE range in the synced NVD data, the
// versions at the range's edges. Those are where a version comparison goes wrong,
// so they are the cases worth labelling. The label column is left blank on
// purpose: a label taken from the same range would only test the matcher against
// itself, so each one has to come from the vendor advisory.
//
//	go run ./devtools/benchsample -vendor apache -product http_server -limit 40
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/BhargavPalan/Fal-X/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "benchsample:", err)
		os.Exit(1)
	}
}

func run() error {
	vendor := flag.String("vendor", "", "CPE vendor")
	product := flag.String("product", "", "CPE product")
	limit := flag.Int("limit", 40, "how many ranged CVEs to list")
	dsn := flag.String("dsn", "", "Postgres connection string (default $FALX_DSN)")
	flag.Parse()
	if *vendor == "" || *product == "" {
		return fmt.Errorf("-vendor and -product are required")
	}
	if *dsn == "" {
		*dsn = store.DSNFromEnv()
	}
	if *dsn == "" {
		return fmt.Errorf("no connection string; pass -dsn or set FALX_DSN")
	}

	ctx := context.Background()
	db, err := store.Open(ctx, store.DefaultOptions(*dsn))
	if err != nil {
		return err
	}
	defer db.Close()

	rows, err := db.SQL().QueryContext(ctx, `
		SELECT cve_id, start_including, start_excluding, end_including, end_excluding
		FROM cve_cpe
		WHERE vendor = $1 AND product = $2 AND vulnerable
		  AND (start_including <> '' OR start_excluding <> '' OR end_including <> '' OR end_excluding <> '')
		ORDER BY cve_id
		LIMIT $3`, *vendor, *product, *limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Println("cve\tedge\tversion\tnvd_says\tlabel")
	for rows.Next() {
		var cve, si, se, ei, ee string
		if err := rows.Scan(&cve, &si, &se, &ei, &ee); err != nil {
			return err
		}
		edge := func(name, v, nvd string) {
			if v != "" {
				fmt.Printf("%s\t%s\t%s\t%s\t\n", cve, name, v, nvd)
			}
		}
		edge("start", si, "affected")
		edge("start", se, "not affected")
		edge("end", ei, "affected")
		edge("end", ee, "not affected")
	}
	return rows.Err()
}
