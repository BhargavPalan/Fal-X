package stage

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/BhargavPalan/Fal-X/internal/logging"
	"github.com/BhargavPalan/Fal-X/internal/run"
	"github.com/BhargavPalan/Fal-X/internal/util"
)

// Targets prepares the target list for an IP or ASN run.
//
// In domain mode there is nothing to do: the roots stage starts from the seeds.
// This stage exists because an ASN expands into netblocks that do not exist until
// they are looked up, and every one of them has to be authorized before a
// scanner sees it.
func Targets(ctx context.Context, e *Env) error {
	if !e.Opts.IPMode {
		e.Run.SetNote("targets", "domain mode, the roots stage starts from the seeds")
		return run.ErrSkip
	}

	out := e.Paths.TargetsFile()

	// An IP or CIDR target was already scope-checked during the precheck, but
	// the stage is also safe to invoke on its own, so it is re-checked here.
	if e.Opts.IPTarget != "" {
		if !e.Gate.Scope().Gate(e.Opts.IPTarget, "") {
			logging.Error("IP target refused by scope: %s", e.Opts.IPTarget)
			e.Run.SetNote("targets", "ip target out of scope")
			return util.WriteLines(out, nil)
		}
		return util.WriteLines(out, []string{e.Opts.IPTarget})
	}

	blocks, err := asnNetblocks(ctx, e)
	if err != nil {
		e.Run.SetNote("targets", err.Error())
		// A present empty file, so a consumer can tell "ran, found nothing"
		// from "crashed before writing".
		if werr := util.WriteLines(out, nil); werr != nil {
			return werr
		}
		return err
	}

	if err := util.WriteLines(e.Paths.NetblocksFile(), blocks); err != nil {
		return err
	}
	if err := util.WriteLines(out, blocks); err != nil {
		return err
	}

	if len(blocks) == 0 {
		logging.Warn("no in-scope netblocks remain for %s", e.Opts.ASN)
		e.Run.SetNote("targets", "no in-scope netblocks")
		return nil
	}

	logging.Ok("asn: %d in-scope netblock(s)", len(blocks))
	return nil
}

// asnNetblocks fetches an ASN's announced prefixes and keeps the authorized ones.
//
// A netblock is only usable when the allowlist authorizes its network address.
// Partial coverage is refused, so a later scan cannot walk outside the
// authorized range.
func asnNetblocks(ctx context.Context, e *Env) ([]string, error) {
	if e.Opts.ASN == "" {
		return nil, nil
	}

	logging.Info("fetching announced prefixes for %s", e.Opts.ASN)

	// RIPEstat is HTTPS only.
	endpoint := "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" +
		url.QueryEscape(e.Opts.ASN)

	body, err := gatedGet(ctx, e, endpoint)
	if err != nil {
		return nil, fmt.Errorf("ripestat lookup failed: %w", err)
	}

	var doc struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("ripestat returned unparseable JSON: %w", err)
	}

	var kept []string
	for _, p := range doc.Data.Prefixes {
		block := strings.TrimSpace(p.Prefix)
		if _, err := netip.ParsePrefix(block); err != nil {
			continue
		}
		if !e.Gate.Scope().Gate(block, "") {
			logging.Debug("netblock outside scope: %s", block)
			continue
		}
		kept = append(kept, block)
	}
	return kept, nil
}

// gatedGet fetches a URL through the gate, returning the body.
//
// It goes through net.Gate rather than building a client, because the gate is
// the only place in the codebase that is allowed to issue a request. That is
// what makes the redirect check and the authorization check unavoidable.
//
// An out-of-scope refusal is returned as an error rather than silently yielding
// an empty body, because an empty body and an unreachable API look the same to
// every caller downstream.
func gatedGet(ctx context.Context, e *Env, rawURL string) ([]byte, error) {
	resp, err := e.Gate.GetContext(ctx, rawURL)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", rawURL, resp.StatusCode)
	}
	return resp.Body, nil
}
