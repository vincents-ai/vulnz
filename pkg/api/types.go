package api

import "time"

type AffectedProduct struct {
	Name    string
	Vendor  string
	Version string
}

type FeedRecord struct {
	// Scores are nullable: absence is not a CVSS score of zero.
	BaseScore           *float64
	BaseScoreVector     string
	BsiSeverity         string
	Cve                 string
	KevExploited        bool
	KevDateAdded        *time.Time
	EnisaEuvdID         string
	EnisaSeverity       string
	BsiAdvisoryID       string
	BsiTr03116Compliant *bool
	Provider            string
	AffectedProducts    []AffectedProduct
}

type FetchResult struct {
	Provider string
	Records  []FeedRecord
	Count    int
}
