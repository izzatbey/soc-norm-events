package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

var sysmonLinuxEvents = []string{
	"sysmon_event1",
	"sysmon_event3",
	"sysmon_event5",
	"sysmon_event9",
	"sysmon_event11",
	"sysmon_event23",
}

func sysmonRemap(raw string) string {
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())
	initiated := strings.ToLower(gjson.Get(raw, "data.eventdata.initiated").String())

	for _, event := range sysmonLinuxEvents {
		if strings.Contains(ruleGroups, event) {
			mapping := map[string]string{
				"data.eventdata.image":             "process.name",
				"data.eventdata.processId":         "process.pid",
				"data.eventdata.commandLine":       "process.command_line",
				"data.eventdata.user":              "process.user",
				"data.eventdata.parentImage":       "process.parent.name",
				"data.eventdata.parentProcessId":   "process.parent.pid",
				"data.eventdata.parentCommandLine": "process.parent.command_line",
				"data.eventdata.parentUser":        "process.parent.user",
				"data.eventdata.sourceIp":          "source.ip",
				"data.eventdata.sourcePort":        "source.port",
				"data.eventdata.destinationIp":     "destination.ip",
				"data.eventdata.destinationPort":   "destination.port",
				"data.eventdata.protocol":          "network.protocol",
				"data.eventdata.device":            "process.device",
				"data.eventdata.targetFilename":    "file.name",
				"data.eventdata.hashes":            "file.hash",
				"data.eventdata.isExecutable":      "file.is_executable",
			}
			raw = renameFields(raw, mapping)

			if strings.Contains(initiated, "true") {
				raw, _ = sjson.Set(raw, "network.direction", "egress")
			} else if strings.Contains(initiated, "false") {
				raw, _ = sjson.Set(raw, "network.direction", "ingress")
			}

			// raw = pkg.extractMitreInfo(raw)
		}
	}
	return cleanSysmonFields(raw)
}

func cleanSysmonFields(raw string) string {
	dropList := []string{
		"data.eventdata.company",
		"data.eventdata.description",
		"data.eventdata.fileVersion",
		"data.eventdata.product",
		"data.eventdata.originalFileName",
		"data.eventdata.integrityLevel",
		"data.eventdata.parentProcessGuid",
		"data.eventdata.processGuid",
		"data.system.keywords",
		"data.system.opcode",
		"data.system.task",
		"data.system.eventRecordID",
		"data.system.processID",
		"data.system.threadID",
		"data.system.version",
		"time",
		"data.system.systemTime",
	}

	for _, key := range dropList {
		if gjson.Get(raw, key).Exists() {
			raw, _ = sjson.Delete(raw, key)
		}
	}

	for _, section := range []string{"data.eventdata", "data.system", "process", "process.parent", "file"} {
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
