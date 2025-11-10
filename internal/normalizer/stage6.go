package normalizer

import (
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func ApplyStage6Rules(raw string) string {
	raw = enrichWithMISP(raw)
	raw = enrichWithEPSS(raw)
	return raw
}

func enrichWithMISP(raw string) string {
	mispURL := "https://10.80.120.12/attributes/restSearch/value:"
	apiKey := "54dnrnEFXv94QnLjhgnM6eHUHY0u6xRS05HOqH9n"

	client := &http.Client{Timeout: 3 * time.Second}

	iocFields := []string{
		"source.ip",
		"destination.ip",
		"file.hash.md5",
		"file.hash.sha1",
		"file.hash.sha256",
		"process.hash.sha256",
		"dns.question.name",
	}

	for _, field := range iocFields {
		value := gjson.Get(raw, field).String()
		if value == "" || isPrivateIP(value) || strings.EqualFold(value, "127.0.0.1") {
			continue
		}

		req, err := http.NewRequest("GET", mispURL+value, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Authorization", apiKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Go-Normalizer-MISP-Lookup")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 200 {
			body, _ := ioutil.ReadAll(resp.Body)
			category := gjson.GetBytes(body, "response.Attribute[0].category").String()
			if category != "" {
				raw, _ = sjson.Set(raw, "misp.category", category)
			}
		}
	}
	return raw
}

func enrichWithEPSS(raw string) string {
	cve := gjson.Get(raw, "data.vulnerability.cve").String()
	if cve == "" {
		return raw
	}

	url := "https://api.first.org/data/v1/epss?cve=" + cve
	client := &http.Client{Timeout: 3 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return raw
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Go-Normalizer-EPSS-Lookup")

	resp, err := client.Do(req)
	if err != nil {
		return raw
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		status := gjson.GetBytes(body, "status").String()
		score := gjson.GetBytes(body, "data.0.epss").String()
		severity := gjson.GetBytes(body, "data.0.percentile").String()

		if status != "" {
			raw, _ = sjson.Set(raw, "epss.status", status)
		}
		if score != "" {
			raw, _ = sjson.Set(raw, "epss.score", score)
		}
		if severity != "" {
			raw, _ = sjson.Set(raw, "epss.percentile", severity)
		}
	}
	return raw
}

func isPrivateIP(ip string) bool {
	privateCIDRs := []string{
		"10.",
		"192.168.",
		"172.16.",
		"127.",
	}
	for _, prefix := range privateCIDRs {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}
