package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func ApplyStage2Rules(raw string) string {
	raw = Event1(raw)
	raw = Event3(raw)
	raw = Event5(raw)
	raw = Event9(raw)
	raw = Event11(raw)
	raw = Event23(raw)
	raw = extractMitreInfo(raw)
	return raw
}

func Event1(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())

	if strings.Contains(decoder, "sysmon-linux") && strings.Contains(ruleGroups, "sysmon_event1") {
		mapping := map[string]string{
			"data.eventdata.image":             "process.name",
			"data.eventdata.processId":         "process.pid",
			"data.eventdata.commandLine":       "process.command_line",
			"data.eventdata.user":              "process.user",
			"data.eventdata.parentImage":       "process.parent.name",
			"data.eventdata.parentProcessId":   "process.parent.pid",
			"data.eventdata.parentCommandLine": "process.parent.command_line",
			"data.eventdata.parentUser":        "process.parent.user",
		}
		raw = renameFields(raw, mapping)
	}
	return cleanSysmonFields(raw)
}

func Event3(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())
	initiated := strings.ToLower(gjson.Get(raw, "data.eventdata.initiated").String())

	if strings.Contains(decoder, "sysmon-linux") && strings.Contains(ruleGroups, "sysmon_event3") {
		mapping := map[string]string{
			"data.eventdata.image":           "process.name",
			"data.eventdata.processId":       "process.pid",
			"data.eventdata.user":            "process.user",
			"data.eventdata.sourceIp":        "source.ip",
			"data.eventdata.sourcePort":      "source.port",
			"data.eventdata.destinationIp":   "destination.ip",
			"data.eventdata.destinationPort": "destination.port",
			"data.eventdata.protocol":        "network.protocol",
		}
		raw = renameFields(raw, mapping)

		if strings.Contains(initiated, "true") {
			raw, _ = sjson.Set(raw, "network.direction", "egress")
		} else if strings.Contains(initiated, "false") {
			raw, _ = sjson.Set(raw, "network.direction", "ingress")
		}
	}
	return cleanSysmonFields(raw)
}

func Event5(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())

	if strings.Contains(decoder, "sysmon-linux") && strings.Contains(ruleGroups, "sysmon_event5") {
		mapping := map[string]string{
			"data.eventdata.image":     "process.name",
			"data.eventdata.processId": "process.pid",
			"data.eventdata.user":      "process.user",
		}
		raw = renameFields(raw, mapping)
	}
	return cleanSysmonFields(raw)
}

func Event9(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())

	if strings.Contains(decoder, "sysmon-linux") && strings.Contains(ruleGroups, "sysmon_event9") {
		mapping := map[string]string{
			"data.eventdata.image":     "process.name",
			"data.eventdata.processId": "process.pid",
			"data.eventdata.user":      "process.user",
			"data.eventdata.device":    "process.device",
		}
		raw = renameFields(raw, mapping)
	}
	return cleanSysmonFields(raw)
}

func Event11(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())

	if strings.Contains(decoder, "sysmon-linux") && strings.Contains(ruleGroups, "sysmon_event11") {
		mapping := map[string]string{
			"data.eventdata.image":          "process.name",
			"data.eventdata.processId":      "process.pid",
			"data.eventdata.user":           "process.user",
			"data.eventdata.targetFilename": "file.name",
		}
		raw = renameFields(raw, mapping)
	}
	return cleanSysmonFields(raw)
}

func Event23(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())

	if strings.Contains(decoder, "sysmon-linux") && strings.Contains(ruleGroups, "sysmon_event23") {
		mapping := map[string]string{
			"data.eventdata.image":          "process.name",
			"data.eventdata.processId":      "process.pid",
			"data.eventdata.user":           "process.user",
			"data.eventdata.targetFilename": "file.name",
			"data.eventdata.hashes":         "file.hash",
			"data.eventdata.isExecutable":   "file.is_executable",
		}
		raw = renameFields(raw, mapping)
	}
	return cleanSysmonFields(raw)
}

// func extractMitreInfo(raw string) string {
// 	ruleName := gjson.Get(raw, "data.eventdata.ruleName").String()
// 	if ruleName == "" || strings.EqualFold(ruleName, "-") {
// 		return raw
// 	}

// 	var techniqueID, techniqueName string
// 	parts := strings.Split(ruleName, ",")
// 	for _, p := range parts {
// 		p = strings.TrimSpace(p)
// 		if strings.HasPrefix(p, "TechniqueID=") {
// 			techniqueID = strings.TrimPrefix(p, "TechniqueID=")
// 		} else if strings.HasPrefix(p, "TechniqueName=") {
// 			techniqueName = strings.TrimPrefix(p, "TechniqueName=")
// 		}
// 	}

// 	if techniqueID != "" {
// 		raw, _ = sjson.Set(raw, "rule.mitre.id", techniqueID)
// 	}
// 	if techniqueName != "" {
// 		raw, _ = sjson.Set(raw, "rule.mitre.technique", techniqueName)
// 	}

// 	// Clean the raw field after parsing
// 	raw, _ = sjson.Delete(raw, "data.eventdata.ruleName")
// 	return raw
// }

// func cleanSysmonFields(raw string) string {
// 	dropList := []string{
// 		"data.eventdata.company",
// 		"data.eventdata.description",
// 		"data.eventdata.fileVersion",
// 		"data.eventdata.product",
// 		"data.eventdata.originalFileName",
// 		"data.eventdata.integrityLevel",
// 		"data.eventdata.parentProcessGuid",
// 		"data.eventdata.processGuid",
// 		"data.system.keywords",
// 		"data.system.opcode",
// 		"data.system.task",
// 		"data.system.eventRecordID",
// 		"data.system.processID",
// 		"data.system.threadID",
// 		"data.system.version",
// 		"time",
// 		"data.system.systemTime",
// 	}

// 	for _, key := range dropList {
// 		if gjson.Get(raw, key).Exists() {
// 			raw, _ = sjson.Delete(raw, key)
// 		}
// 	}

// 	for _, section := range []string{"data.eventdata", "data.system", "process", "process.parent", "file"} {
// 		obj := gjson.Get(raw, section)
// 		if obj.Exists() && obj.IsObject() {
// 			for k, v := range obj.Map() {
// 				strVal := strings.TrimSpace(v.String())
// 				if strVal == "" || strVal == "-" || strings.EqualFold(strVal, "null") {
// 					raw, _ = sjson.Delete(raw, section+"."+k)
// 				}
// 			}
// 		}
// 	}
// 	return raw
// }
