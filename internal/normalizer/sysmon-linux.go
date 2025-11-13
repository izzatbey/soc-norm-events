package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
)

var sysmonLinuxEvents = []string{
	"sysmon_event1",
	"sysmon_event3",
	"sysmon_event5",
	"sysmon_event9",
	"sysmon_event11",
	"sysmon_event23",
}

func sysmonLinuxRemap(raw string) string {
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())
	initiated := strings.ToLower(gjson.Get(raw, "data.eventdata.initiated").String())
	linuxMitre := gjson.Get(raw, "data.eventdata.ruleName").String()

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
				"data.eventdata.DestinationIp":     "destination.ip",
				"data.eventdata.destinationPort":   "destination.port",
				"data.eventdata.protocol":          "network.protocol",
				"data.eventdata.device":            "process.device",
				"data.eventdata.targetFilename":    "file.name",
				"data.eventdata.hashes":            "file.hash.combined",
				"data.eventdata.isExecutable":      "file.is_executable",
			}
			raw = renameFields(raw, mapping)
			raw = setNetworkDirection(raw, initiated)
			raw = extractMitreInfo(raw, linuxMitre)
		}
	}
	return cleanFields(raw)
}
