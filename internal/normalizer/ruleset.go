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

	raw = standardizeEvent(raw)
	raw = ApplyAlertRules(raw)
	return raw
}

func SourceCategory(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	location := strings.ToLower(gjson.Get(raw, "location").String())

	switch {
	case strings.Contains(decoder, "fortigate"):
		return "fortigate"
	case strings.Contains(decoder, "sysmon-linux"):
		return "sysmon-linux"
	case strings.Contains(decoder, "windows_eventchannel"):
		return "sysmon-windows"
	case strings.Contains(decoder, "web-accesslog") && strings.Contains(location, "nginx"):
		return "nginx"
	default:
		return "hostname"
	}
}

var ruleRouter = map[string][]func(string) string{
	"fortigate": {
		fortigateRemap,
	},
	"sysmon-linux": {
		sysmonLinuxRemap,
	},
	"sysmon-windows": {
		sysmonWinRemap,
	},
	"nginx": {
		nginxRemap,
	},
	"hostname": {
		hostnameRemap,
	},
}
