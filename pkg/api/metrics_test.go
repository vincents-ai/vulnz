package api

import "testing"

func TestProviderMetricsPreserved(t *testing.T) {
	r := convertEUVD("CVE-test", map[string]interface{}{"baseScore": 9.8, "baseScoreVector": "CVSS:3.1/test"})
	if r.BaseScore == nil || *r.BaseScore != 9.8 || r.BaseScoreVector != "CVSS:3.1/test" {
		t.Fatal("EUVD metrics lost")
	}
	r = convertBSI("CVE-test", map[string]interface{}{"metadata": map[string]interface{}{"aggregate_severity_de": "hoch"}})
	if r.BsiSeverity != "hoch" || r.BaseScore != nil {
		t.Fatal("BSI severity lost or score fabricated")
	}
	for _, score := range []float64{0, 7.5} {
		r = convertEUVD("CVE-test", map[string]interface{}{"baseScore": score})
		if r.BaseScore == nil || *r.BaseScore != score {
			t.Fatal("valid score lost")
		}
	}
	for _, score := range []interface{}{nil, -1.0, 11.0, "bad"} {
		r = convertEUVD("CVE-test", map[string]interface{}{"baseScore": score})
		if r.BaseScore != nil {
			t.Fatal("invalid score accepted")
		}
	}
}
