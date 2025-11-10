package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func ApplyStage1Rules(raw string) string {
	raw = applyHostnameRemapRules(raw)
	programName := strings.ToLower(gjson.Get(raw, "predecoder.program_name").String())
	if programName == "fluent-bit" {
		return ""
	}

	decoder := gjson.Get(raw, "decoder.name").String()

	if strings.Contains(decoder, "fortigate") {
		raw = fortigateDirectionRule(raw)
		raw = fortigateRemapRule(raw)
		raw = fortigateCleanupRule(raw)
	}

	return raw
}

func applyHostnameRemapRules(raw string) string {
	hostnameMap := map[string]string{
		"NTNX-":            "nutanix",
		"vmware-esxi":      "vmware-esxi",
		"2024":             "h3c",
		"ckr_jtp_01":       "hsm_dc",
		"sby_jtp_01":       "hsm_drc",
		"ESIGNISSUINGCA01": "ejbca_ESIGNISSUINGCA01",
		"node-OeLJPOttvU":  "ejbca_node-OeLJPOttvU",
		"node-INWxaXczjk":  "ejbca_node-INWxaXczjk",
	}

	candidates := []string{
		"predecoder.hostname",
		"decoder.name",
	}

	for _, path := range candidates {
		v := gjson.Get(raw, path)
		if !v.Exists() {
			continue
		}

		value := v.String()
		for substring, agent := range hostnameMap {
			if strings.Contains(value, substring) {
				raw, _ = sjson.Set(raw, "agent.name", agent)

				if gjson.Get(raw, "time").Exists() {
					raw, _ = sjson.Delete(raw, "time")
				}

				return raw
			}
		}
	}

	return raw
}

func fortigateDirectionRule(raw string) string {
	srcRole := strings.ToLower(gjson.Get(raw, "data.srcintfrole").String())
	dstRole := strings.ToLower(gjson.Get(raw, "data.dstintfrole").String())

	switch {
	case strings.Contains(srcRole, "wan"):
		raw, _ = sjson.Set(raw, "network.direction", "inbound")
	case strings.Contains(dstRole, "wan"):
		raw, _ = sjson.Set(raw, "network.direction", "outbound")
	case srcRole != "" && dstRole != "":
		raw, _ = sjson.Set(raw, "network.direction", "internal")
	}
	return raw
}

func fortigateRemapRule(raw string) string {
	mapping := map[string]string{
		"data.devname":    "agent.name",
		"data.remip":      "source.ip",
		"data.srcip":      "source.ip",
		"data.srcport":    "source.port",
		"data.dstuser":    "destination.user",
		"data.dstip":      "destination.ip",
		"data.dstport":    "destination.port",
		"data.service":    "network.protocol",
		"data.srccountry": "source.geo.country_name",
		"data.dstcountry": "destination.geo.country_name",
	}

	for old, new := range mapping {
		if v := gjson.Get(raw, old); v.Exists() {
			raw, _ = sjson.Set(raw, new, v.Value())
			raw, _ = sjson.Delete(raw, old)
		}
	}
	return raw
}

func fortigateCleanupRule(raw string) string {
	for _, f := range []string{"data.devname", "predecoder.hostname", "data.time", "time", "data.eventtime"} {
		if gjson.Get(raw, f).Exists() {
			raw, _ = sjson.Delete(raw, f)
		}
	}

	data := gjson.Get(raw, "data")
	if data.Exists() && data.IsObject() {
		for k, v := range data.Map() {
			if v.Type == gjson.String {
				if strings.TrimSpace(v.String()) == "N/A" {
					raw, _ = sjson.Delete(raw, "data."+k)
				}
			}
		}
	}

	return raw
}
