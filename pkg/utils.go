package pkg

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func extractMitreInfo(raw string) string {
	ruleName := gjson.Get(raw, "data.eventdata.ruleName").String()
	if ruleName == "" || strings.EqualFold(ruleName, "-") {
		return raw
	}

	var techniqueID, techniqueName string
	parts := strings.Split(ruleName, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "TechniqueID=") {
			techniqueID = strings.TrimPrefix(p, "TechniqueID=")
		} else if strings.HasPrefix(p, "TechniqueName=") {
			techniqueName = strings.TrimPrefix(p, "TechniqueName=")
		}
	}

	if techniqueID != "" {
		raw, _ = sjson.Set(raw, "rule.mitre.id", techniqueID)
	}
	if techniqueName != "" {
		raw, _ = sjson.Set(raw, "rule.mitre.technique", techniqueName)
	}

	// Clean the raw field after parsing
	raw, _ = sjson.Delete(raw, "data.eventdata.ruleName")
	return raw
}

func renameFields(raw string, mapping map[string]string) string {
	for oldField, newField := range mapping {
		if val := gjson.Get(raw, oldField); val.Exists() {
			raw, _ = sjson.Set(raw, newField, val.Value())
			raw, _ = sjson.Delete(raw, oldField)
		}
	}
	return raw
}
