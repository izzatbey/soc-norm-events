package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func hostnameRemap(raw string) string {
	hostnameMap := map[string]string{
		"NTNX-":            "nutanix",
		"vmware-esxi":      "vmware-esxi",
		"2025":             "h3c",
		"ckr_jtp_01":       "hsm_dc",
		"sby_jtp_01":       "hsm_drc",
		"ESIGNISSUINGCA01": "ejbca_ESIGNISSUINGCA01",
		"node-OeLJPOttvU":  "ejbca_node-OeLJPOttvU",
		"node-INWxaXczjk":  "ejbca_node-INWxaXczjk",
	}

	candidates := []string{
		"predecoder.hostname",
		"decoder.name",
		"agent.name",
	}

	for _, path := range candidates {
		value := gjson.Get(raw, path).String()
		if value == "" {
			continue
		}

		for substring, mappedAgent := range hostnameMap {
			if strings.Contains(strings.ToLower(value), strings.ToLower(substring)) {
				raw, _ = sjson.Set(raw, "agent.name", mappedAgent)

				for _, field := range []string{"time", "data.time"} {
					if gjson.Get(raw, field).Exists() {
						raw, _ = sjson.Delete(raw, field)
					}
				}
				return raw
			}
		}
	}

	return raw
}

func fortigateDirection(raw string) string {
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

func fortigateRemap(raw string) string {
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

	raw = fortigateDirection(raw)
	for old, new := range mapping {
		if v := gjson.Get(raw, old); v.Exists() {
			raw, _ = sjson.Set(raw, new, v.Value())
			raw, _ = sjson.Delete(raw, old)
		}
	}

	return cleanFields(raw)
}
