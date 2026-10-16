// SPDX-License-Identifier: GPL-3.0-or-later

// Command sharza-probe is a development-only, manually-run end-to-end probe
// for the Gnutella engine. It loads the daemon's own configuration, starts the
// real engine, searches for a term, and downloads the smallest file a live
// QUERYHIT advertises.
//
// It exists to produce the P1 exit-gate evidence a scripted peer cannot: a
// search and a download against a real Gnutella node. It is not part of any
// package, is never built into the daemon or the .deb, and is never invoked by
// `go test` or CI. Run it by hand:
//
//	go run ./cmd/sharza-probe -config cfg.json -term "..." -dir /tmp/sharza-probe
//
// Exit status is 0 only when a transfer completed with the advertised size.
// Anything else is a recorded negative result, printed to stderr with what was
// and was not observed.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/config"
	"github.com/jonathanvanherpe/sharza/internal/engine/gnutella"
)

// candidate pairs a QUERYHIT with one file it advertised. The QUERYHIT carries
// the source address the download GET is sent to, so the pair cannot be split.
type candidate struct {
	qh  gnutella.QueryHit
	hit gnutella.FileHit
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, stamp()+" sharza-probe: FAIL: "+err.Error())
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath    = flag.String("config", "", "path to a sharza config JSON (empty uses built-in defaults)")
		term          = flag.String("term", "", "search term to send (required)")
		dir           = flag.String("dir", "/tmp/sharza-probe", "directory to download into")
		timeout       = flag.Duration("timeout", 180*time.Second, "overall deadline for the run")
		searchTimeout = flag.Duration("search-timeout", 15*time.Second, "window one Search waits for QUERYHITs")
		poll          = flag.Duration("poll", 3*time.Second, "pause between empty searches")
		listen        = flag.String("listen", "", "override the configured Gnutella listen address")
		maxSize       = flag.Uint64("max-size", 64<<20, "largest file to download, in bytes")
	)
	flag.Parse()

	if *term == "" {
		flag.Usage()
		return errors.New("-term is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ln := cfg.GnutellaListen
	if *listen != "" {
		ln = *listen
	}

	logf("config: listen=%s peers=%v caches=%v", ln, cfg.GnutellaPeers, cfg.GnutellaCaches)
	logf("term=%q dir=%s max-size=%d timeout=%s search-timeout=%s", *term, *dir, *maxSize, *timeout, *searchTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	eng := gnutella.New()
	runErr := make(chan error, 1)
	go func() {
		runErr <- eng.Run(ctx, gnutella.Options{
			Listen:        ln,
			Peers:         cfg.GnutellaPeers,
			Caches:        cfg.GnutellaCaches,
			SearchTimeout: *searchTimeout,
			Logf:          engineLogf,
		})
	}()

	select {
	case <-eng.Ready():
		logf("engine ready on %s", eng.Addr())
	case err := <-runErr:
		return fmt.Errorf("engine stopped before it was ready: %w", err)
	case <-ctx.Done():
		return fmt.Errorf("engine was not ready before the %s deadline: %w", *timeout, ctx.Err())
	}

	hits, err := collectHits(ctx, eng, *term, *searchTimeout, *poll)
	if err != nil {
		return err
	}

	cands := flatten(hits)
	if len(cands) == 0 {
		return errors.New("queryhits arrived but advertised no files")
	}
	best, err := choose(cands, *maxSize)
	if err != nil {
		return err
	}
	logf("selected %q size=%d from %s (index %d)",
		best.hit.FileName, best.hit.FileSize, best.qh.Source(), best.hit.FileIndex)

	dctx, dcancel := context.WithTimeout(ctx, *timeout)
	defer dcancel()
	res, err := eng.Downloader(best.qh, best.hit).Fetch(dctx, *dir)
	if err != nil {
		return fmt.Errorf("download from %s failed: %w", best.qh.Source(), err)
	}

	fi, err := os.Stat(res.Path)
	if err != nil {
		return fmt.Errorf("stat %s after download: %w", res.Path, err)
	}
	if fi.Size() != int64(best.hit.FileSize) {
		return fmt.Errorf("on-disk size %d != advertised %d for %s",
			fi.Size(), best.hit.FileSize, res.Path)
	}
	logf("downloaded %s: %d bytes at offset %d, on-disk size %d == advertised size %d",
		res.Path, res.Bytes, res.Offset, fi.Size(), best.hit.FileSize)

	cancel()
	select {
	case err := <-runErr:
		if err != nil {
			logf("engine stopped: %v", err)
		}
	case <-time.After(5 * time.Second):
		logf("engine did not stop within 5s of cancel")
	}
	logf("PASS: completed a search and a download against the live swarm")
	return nil
}

// collectHits polls Search until it returns at least one QUERYHIT or the
// context ends. The engine has no exported peer count, so a search that
// returns with no hits almost immediately (well inside its own window) is the
// observable signal that no peer is connected yet; the loop then waits for the
// dial and cache loops to produce one and tries again.
func collectHits(ctx context.Context, eng *gnutella.Engine, term string, searchWindow, poll time.Duration) ([]gnutella.QueryHit, error) {
	attempt := 0
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no queryhits for %q before the deadline: %w", term, ctx.Err())
		default:
		}
		attempt++
		start := time.Now()
		hits, err := eng.Search(term)
		elapsed := time.Since(start)
		if err != nil {
			logf("search %d: write error: %v", attempt, err)
		}
		if len(hits) > 0 {
			logf("search %d: %d queryhit(s) in %s", attempt, len(hits), elapsed.Round(time.Millisecond))
			return hits, nil
		}
		if elapsed < searchWindow/2 {
			logf("search %d: no hits in %s (returned early, so no connected peers yet)", attempt, elapsed.Round(time.Millisecond))
		} else {
			logf("search %d: window %s closed with no hits", attempt, elapsed.Round(time.Millisecond))
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("no queryhits for %q before the deadline: %w", term, ctx.Err())
		case <-time.After(poll):
		}
	}
}

// flatten turns the QUERYHITs a search returned into one candidate per file,
// logging every advertised file so a transcript shows the whole result set
// rather than only the one that was chosen.
func flatten(hits []gnutella.QueryHit) []candidate {
	var cands []candidate
	for _, qh := range hits {
		src := qh.Source()
		for _, h := range qh.Hits {
			logf("hit: source=%s name=%q size=%d index=%d speed=%d", src, h.FileName, h.FileSize, h.FileIndex, qh.Speed)
			cands = append(cands, candidate{qh: qh, hit: h})
		}
	}
	return cands
}

// choose returns the smallest file with a positive size at or below maxSize.
// A zero-length hit cannot satisfy the size check, and a file above maxSize is
// refused rather than pulled; if every hit falls outside the window, that is a
// recorded negative result, not a trigger to download a movie.
func choose(cands []candidate, maxSize uint64) (candidate, error) {
	best := -1
	var tooBig, zero int
	for i, c := range cands {
		switch {
		case c.hit.FileSize == 0:
			zero++
		case uint64(c.hit.FileSize) > maxSize:
			tooBig++
		case best < 0 || c.hit.FileSize < cands[best].hit.FileSize:
			best = i
		}
	}
	if best < 0 {
		return candidate{}, fmt.Errorf("no hit within -max-size=%d (%d zero-length, %d over the cap)",
			maxSize, zero, tooBig)
	}
	logf("candidates: %d usable, %d zero-length, %d over the %d-byte cap", len(cands)-zero-tooBig, zero, tooBig, maxSize)
	return cands[best], nil
}

func stamp() string {
	return time.Now().Format("2006-01-02T15:04:05.000")
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, stamp()+" sharza-probe: "+format+"\n", args...)
}

func engineLogf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, stamp()+" sharza-probe: gnutella: "+format+"\n", args...)
}
