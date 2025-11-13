package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// alertMapping defines MITRE tactic → numeric ID mapping.
var mitreTacticIDMap = map[string]int{
	"Reconnaissance":       37,
	"Resource Development": 38,
	"Initial Access":       39,
	"Execution":            40,
	"Persistence":          41,
	"Privilege Escalation": 42,
	"Defense Evasion":      43,
	"Credential Access":    44,
	"Discovery":            45,
	"Lateral Movement":     46,
	"Collection":           47,
	"Command and Control":  48,
	"Exfiltration":         49,
	"Impact":               50,
}

func ApplyAlertRules(raw string) string {
	raw = mapIrisSeverity(raw)
	raw = mapAlertSource(raw)
	raw = mapMitreTacticID(raw)
	return raw
}

func mapIrisSeverity(raw string) string {
	ruleLevel := gjson.Get(raw, "rule.level")
	if !ruleLevel.Exists() {
		return raw
	}

	val := ruleLevel.Int()
	var severity string

	switch {
	case val <= 2:
		severity = "2"
	case val >= 3 && val <= 5:
		severity = "3"
	case val >= 6 && val <= 8:
		severity = "4"
	case val >= 9 && val <= 12:
		severity = "5"
	case val >= 13:
		severity = "6"
	default:
		return raw
	}

	raw, _ = sjson.Set(raw, "iris.severity.level", severity)
	return raw
}

func mapAlertSource(raw string) string {
	logTag := strings.ToLower(gjson.Get(raw, "log.tag").String())

	switch logTag {
	case "wazuh-dc":
		raw, _ = sjson.Set(raw, "source.alert", "Kafka-1")
	case "wazuh-drc":
		raw, _ = sjson.Set(raw, "source.alert", "Kafka-2")
	}

	return raw
}

func mapMitreTacticID(raw string) string {
	tactic := gjson.Get(raw, "rule.mitre.tactic").String()
	if tactic == "" {
		return raw
	}

	for key, id := range mitreTacticIDMap {
		if strings.Contains(tactic, key) {
			raw, _ = sjson.Set(raw, "rule.mitre.tactic_id", id)
			break
		}
	}

	return raw
}
