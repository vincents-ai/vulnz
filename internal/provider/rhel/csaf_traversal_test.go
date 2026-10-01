package rhel

import (
	"path/filepath"
	"testing"
)

// The deletions manifest is DOWNLOADED DATA, and its entries were joined
// straight onto the advisories directory and then removed. filepath.Join cleans
// its result, so base + "../../../etc/passwd" resolves OUTSIDE base and the
// caller proceeded to delete it. The removal error was also discarded, so a
// failed deletion was silent.
//
// These tests pin the containment guarantee, because "filepath.Join looked safe"
// is exactly the reasoning that produced the defect.
func TestSafeJoinRefusesEscapingFragments(t *testing.T) {
	base := t.TempDir()

	escapes := []string{
		"../etc/passwd",
		"../../../../etc/shadow",
		"a/../../outside.json",
		"./../sibling",
	}
	for _, frag := range escapes {
		if _, err := safeJoin(base, frag); err == nil {
			t.Errorf("fragment %q must be refused; it resolves outside the base", frag)
		}
	}

	abs := filepath.Join(t.TempDir(), "elsewhere.json")
	if _, err := safeJoin(base, abs); err == nil {
		t.Error("an absolute fragment must be refused")
	}
	if _, err := safeJoin(base, ""); err == nil {
		t.Error("an empty fragment must be refused")
	}
}

func TestSafeJoinAcceptsLegitimateFragments(t *testing.T) {
	base := t.TempDir()
	for _, frag := range []string{"CVE-2024-0001.json", "2024/CVE-2024-0001.json", "./CVE-2024-0001.json"} {
		got, err := safeJoin(base, frag)
		if err != nil {
			t.Errorf("legitimate fragment %q was refused: %v", frag, err)
			continue
		}
		if !filepath.IsAbs(got) || filepath.Dir(got) != filepath.Clean(base) {
			// Only a sibling-of-base result is required here; the important part
			// is that it was accepted and stayed inside.
			rel, relErr := filepath.Rel(base, got)
			if relErr != nil || filepath.IsAbs(rel) || len(rel) > 1 && rel[:2] == ".." {
				t.Errorf("fragment %q resolved outside the base: %s", frag, got)
			}
		}
	}
}

// A sibling directory whose name shares the base's prefix must not pass the
// prefix check, which is why the separator is part of the comparison.
func TestSafeJoinDoesNotAcceptSiblingWithSharedPrefix(t *testing.T) {
	base := filepath.Join(t.TempDir(), "advisories")
	sibling := filepath.Join(filepath.Dir(base), "advisories-old")
	if _, err := safeJoin(sibling, "x.json"); err != nil {
		t.Fatalf("a legitimate path was refused: %v", err)
	}
	// And the containment check itself: a fragment that climbs out of base.
	if _, err := safeJoin(base, "../advisories-old/x.json"); err == nil {
		t.Error("climbing into a sibling with a shared prefix must be refused")
	}
}
