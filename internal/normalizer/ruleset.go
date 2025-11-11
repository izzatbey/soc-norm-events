package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
)

func ApplyRules(raw string) string {
	if raw == "" {
		return raw
	}
	raw = hostnameRemap(raw)
	category := SourceCategory(raw)

	if rules, exists := ruleRouter[category]; exists {
		for _, ruleFunc := range rules {
			raw = ruleFunc(raw)
		}
	}

	return raw
}

func SourceCategory(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())

	switch {
	case strings.Contains(decoder, "fortigate"):
		return "fortigate"
	case strings.Contains(decoder, "sysmon-linux"):
		return "sysmon-linux"
	default:
		return "unknown"
	}
}

var ruleRouter = map[string][]func(string) string{
	"fortigate": {
		fortigateDirection,
		fortigateRemap,
		fortigateCleanup,
	},
	"sysmon-linux": {
		sysmonRemap,
	},
}
