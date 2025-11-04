package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func ApplyStage3Rules(raw string) string {
	raw = EventWindows1(raw)
	raw = EventWindows3(raw)
	raw = EventWindows5(raw)
	raw = EventWindows7(raw)
	raw = EventWindows9(raw)
	raw = EventWindows10(raw)
	raw = EventWindows11(raw)
	raw = EventWindows12(raw)
	raw = EventWindows13(raw)
	raw = EventWindows15(raw)
	raw = EventWindows17(raw)
	raw = EventWindows22(raw)
	raw = EventWindows23(raw)
	raw = EventWindowsFallback(raw)
	return raw
}

func EventWindows1(raw string) string {
	if !matchEvent(raw, "sysmon_event1") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":             "process.name",
		"data.win.eventdata.processId":         "process.pid",
		"data.win.eventdata.commandLine":       "process.command_line",
		"data.win.eventdata.user":              "process.user",
		"data.win.eventdata.company":           "process.company",
		"data.win.eventdata.product":           "process.company_product",
		"data.win.eventdata.hashes":            "process.hash",
		"data.win.eventdata.integrityLevel":    "process.integrity_level",
		"data.win.eventdata.currentDirectory":  "process.cwd",
		"data.win.eventdata.logonId":           "process.logon_id",
		"data.win.eventdata.parentImage":       "process.parent.name",
		"data.win.eventdata.parentProcessId":   "process.parent.pid",
		"data.win.eventdata.parentCommandLine": "process.parent.command_line",
		"data.win.eventdata.parentUser":        "process.parent.user",
	}
	raw = renameFields(raw, mapping)
	raw = extractWindowsMitre(raw)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows3(raw string) string {
	if !matchEvent(raw, "sysmon_event3") {
		return raw
	}

	initiated := strings.ToLower(gjson.Get(raw, "data.win.eventdata.initiated").String())

	mapping := map[string]string{
		"data.win.eventdata.image":           "process.name",
		"data.win.eventdata.processId":       "process.pid",
		"data.win.eventdata.user":            "process.user",
		"data.win.eventdata.sourceIp":        "source.ip",
		"data.win.eventdata.sourcePort":      "source.port",
		"data.win.eventdata.destinationIp":   "destination.ip",
		"data.win.eventdata.destinationPort": "destination.port",
		"data.win.eventdata.protocol":        "network.protocol",
	}
	raw = renameFields(raw, mapping)

	if strings.Contains(initiated, "true") {
		raw, _ = sjson.Set(raw, "network.direction", "egress")
	} else if strings.Contains(initiated, "false") {
		raw, _ = sjson.Set(raw, "network.direction", "ingress")
	}

	raw = extractWindowsMitre(raw)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows5(raw string) string {
	if !matchEvent(raw, "sysmon_event5") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":     "process.name",
		"data.win.eventdata.processId": "process.pid",
		"data.win.eventdata.user":      "process.user",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows7(raw string) string {
	if !matchEvent(raw, "sysmon_event7") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":            "process.name",
		"data.win.eventdata.processId":        "process.pid",
		"data.win.eventdata.company":          "process.company",
		"data.win.eventdata.imageLoaded":      "process.dll.path",
		"data.win.eventdata.signature":        "process.dll.signature",
		"data.win.eventdata.signed":           "process.dll.signed",
		"data.win.eventdata.signatureStatus":  "process.dll.signature_status",
		"data.win.eventdata.hashes":           "process.dll.hash",
		"data.win.eventdata.originalFileName": "process.dll.name",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows9(raw string) string {
	if !matchEvent(raw, "sysmon_event9") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":     "process.name",
		"data.win.eventdata.processId": "process.pid",
		"data.win.eventdata.user":      "process.user",
		"data.win.eventdata.device":    "process.device",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows10(raw string) string {
	if !matchEvent(raw, "sysmon_event_10") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.sourceImage":   "process.source_image",
		"data.win.eventdata.targetImage":   "process.target_image",
		"data.win.eventdata.grantedAccess": "process.granted_access",
		"data.win.eventdata.callTrace":     "process.call_trace",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows11(raw string) string {
	if !matchEvent(raw, "sysmon_event_11") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":          "process.name",
		"data.win.eventdata.processId":      "process.pid",
		"data.win.eventdata.user":           "process.user",
		"data.win.eventdata.targetFilename": "process.target_file_name",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows12(raw string) string {
	if !matchEvent(raw, "sysmon_event_12") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":        "process.name",
		"data.win.eventdata.processId":    "process.pid",
		"data.win.eventdata.targetObject": "process.target_object",
		"data.win.eventdata.eventType":    "process.event",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows13(raw string) string {
	if !matchEvent(raw, "sysmon_event_13") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":        "process.name",
		"data.win.eventdata.processId":    "process.pid",
		"data.win.eventdata.targetObject": "process.target_object",
		"data.win.eventdata.eventType":    "process.event",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows15(raw string) string {
	if !matchEvent(raw, "sysmon_event_15") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":          "process.name",
		"data.win.eventdata.processId":      "process.pid",
		"data.win.eventdata.user":           "process.user",
		"data.win.eventdata.targetFilename": "process.target_file_name",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows17(raw string) string {
	if !matchEvent(raw, "sysmon_event_17") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":     "process.name",
		"data.win.eventdata.processId": "process.pid",
		"data.win.eventdata.pipeName":  "process.pipe_name",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows22(raw string) string {
	if !matchEvent(raw, "sysmon_event_22") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":        "process.name",
		"data.win.eventdata.processId":    "process.pid",
		"data.win.eventdata.queryName":    "process.dns.query",
		"data.win.eventdata.queryResults": "process.dns.answer",
		"data.win.eventdata.queryStatus":  "process.dns.response_code",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindows23(raw string) string {
	if !matchEvent(raw, "sysmon_event_23") {
		return raw
	}

	mapping := map[string]string{
		"data.win.eventdata.image":          "process.name",
		"data.win.eventdata.processId":      "process.pid",
		"data.win.eventdata.user":           "process.user",
		"data.win.eventdata.targetFilename": "process.target_file_name",
		"data.win.eventdata.hashes":         "process.hash",
		"data.win.eventdata.isExecutable":   "process.target_is_executable",
	}
	raw = renameFields(raw, mapping)
	return cleanWindowsSysmonFields(raw)
}

func EventWindowsFallback(raw string) string {
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())
	hasProcID := gjson.Get(raw, "data.win.eventdata.processId").Exists()

	if strings.Contains(ruleGroups, "windows") && !hasProcID {
		if val := gjson.Get(raw, "data.win.system.processID"); val.Exists() {
			raw, _ = sjson.Set(raw, "process.pid", val.Value())
			raw, _ = sjson.Delete(raw, "data.win.system.processID")
		}
	}
	return cleanWindowsSysmonFields(raw)
}

func matchEvent(raw, eventGroup string) bool {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())
	return strings.Contains(decoder, "windows_eventchannel") && strings.Contains(ruleGroups, eventGroup)
}

func extractWindowsMitre(raw string) string {
	ruleName := gjson.Get(raw, "data.win.eventdata.ruleName").String()
	if ruleName == "" || ruleName == "-" {
		return raw
	}

	var techniqueID, techniqueName string
	parts := strings.Split(ruleName, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToLower(p), "technique_id=") {
			techniqueID = strings.TrimPrefix(p, "technique_id=")
		} else if strings.HasPrefix(strings.ToLower(p), "technique_name=") {
			techniqueName = strings.TrimPrefix(p, "technique_name=")
		}
	}

	if techniqueID != "" {
		raw, _ = sjson.Set(raw, "rule.mitre.id", techniqueID)
	}
	if techniqueName != "" {
		raw, _ = sjson.Set(raw, "rule.mitre.technique", techniqueName)
	}

	raw, _ = sjson.Delete(raw, "data.win.eventdata.ruleName")
	return raw
}

func cleanWindowsSysmonFields(raw string) string {
	dropList := []string{
		"data.win.eventdata.fileVersion",
		"data.win.eventdata.parentProcessGuid",
		"data.win.eventdata.processGuid",
		"data.win.system.eventRecordID",
		"data.win.system.threadID",
		"data.win.system.task",
		"data.win.system.keywords",
		"data.win.system.opcode",
		"data.win.system.version",
		"data.win.system.severityValue",
		"data.win.system.message",
		"data.win.system.channel",
		"data.win.system.providerGuid",
		"data.win.system.providerName",
		"data.win.eventdata.utcTime",
		"process.company",
	}

	for _, key := range dropList {
		if gjson.Get(raw, key).Exists() {
			raw, _ = sjson.Delete(raw, key)
		}
	}

	for _, section := range []string{
		"data.win.eventdata",
		"data.win.system",
		"process",
		"process.parent",
		"source",
		"destination",
		"network",
	} {
		obj := gjson.Get(raw, section)
		if obj.Exists() && obj.IsObject() {
			for k, v := range obj.Map() {
				strVal := strings.TrimSpace(v.String())
				if strVal == "" || strVal == "-" || strings.EqualFold(strVal, "null") {
					raw, _ = sjson.Delete(raw, section+"."+k)
				}
			}
		}
	}
	return raw
}
