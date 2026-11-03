package main

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// Global search: the box at the top of every page looks through monitored entities,
// findings (any status) and the asset inventory at once. The MCP "search" tool uses
// the same function, so people and AI assistants see the same results.

const (
	searchMinLen   = 2
	searchMaxLen   = 100
	searchPerGroup = 25
)

// SearchResults holds the matches for one query, each group capped at searchPerGroup.
type SearchResults struct {
	Query                                 string
	Targets                               []*Target
	Findings                              []Finding
	Assets                                []Asset
	FindingTotal, AssetTotal, TargetTotal int
}

// Count is the number of matches across all groups (before capping).
func (r *SearchResults) Count() int { return r.TargetTotal + r.FindingTotal + r.AssetTotal }

// cleanQuery trims a search query and reports whether it is long enough to run.
func cleanQuery(q string) (string, bool) {
	q = strings.TrimSpace(q)
	if len([]rune(q)) > searchMaxLen {
		q = string([]rune(q)[:searchMaxLen])
	}
	return q, len([]rune(q)) >= searchMinLen
}

// searchAll runs a case-insensitive text match over entities, findings and assets.
func (s *Server) searchAll(q string, perGroup int) (*SearchResults, error) {
	res := &SearchResults{Query: q}
	needle := strings.ToLower(q)

	ts, err := s.store.ListTargets()
	if err != nil {
		return nil, err
	}
	for _, t := range ts {
		if strings.Contains(strings.ToLower(t.Domain+" "+t.Notes), needle) {
			res.TargetTotal++
			if len(res.Targets) < perGroup {
				res.Targets = append(res.Targets, t)
			}
		}
	}

	fs, err := s.store.ListFindings("", "")
	if err != nil {
		return nil, err
	}
	var hits []Finding
	for _, f := range fs {
		i := describeFinding(f)
		if strings.Contains(strings.ToLower(strings.Join([]string{f.Host, f.Root, f.Kind, f.Detail, i.Title}, " ")), needle) {
			hits = append(hits, f)
		}
	}
	// open first, then worst first, then newest
	sort.SliceStable(hits, func(i, j int) bool {
		if a, b := hits[i].Status == "open", hits[j].Status == "open"; a != b {
			return a
		}
		if a, b := sevRank(hits[i].Severity), sevRank(hits[j].Severity); a != b {
			return a > b
		}
		return hits[i].ID > hits[j].ID
	})
	res.FindingTotal = len(hits)
	if len(hits) > perGroup {
		hits = hits[:perGroup]
	}
	res.Findings = hits

	assets, _, err := s.store.ListAssets("", "", q)
	if err != nil {
		return nil, err
	}
	res.AssetTotal = len(assets)
	if len(assets) > perGroup {
		assets = assets[:perGroup]
	}
	res.Assets = assets
	return res, nil
}

// search is the results page for the search box.
func (s *Server) search(w http.ResponseWriter, r *http.Request, sess *Session) {
	q, ok := cleanQuery(r.URL.Query().Get("q"))
	data := map[string]any{"Title": "Search", "SearchQ": q, "TooShort": !ok && q != "", "MinLen": searchMinLen}
	if ok {
		res, err := s.searchAll(q, searchPerGroup)
		if err != nil {
			s.serverError(w, r, sess, err)
			return
		}
		data["R"] = res
		data["AssetsLink"] = "q=" + url.QueryEscape(q)
	}
	s.render(w, r, sess, "search", http.StatusOK, data)
}
