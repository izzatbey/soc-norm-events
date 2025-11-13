package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
)

var sysmonWinEvents = []string{
	"sysmon_event1",
	"sysmon_event3",
	"sysmon_event5",
	"sysmon_event7",
	"sysmon_event9",
	"sysmon_event_10",
	"sysmon_event_11",
	"sysmon_event_12",
	"sysmon_event_13",
	"sysmon_event_15",
	"sysmon_event_17",
	"sysmon_event_22",
	"sysmon_event_23",
	"windows",
}

func sysmonWinRemap(raw string) string {
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())
	initiated := strings.ToLower(gjson.Get(raw, "data.win.eventdata.initiated").String())
	winMitre := strings.ToLower(gjson.Get(raw, "data.win.eventdata.ruleName").String())

	for _, event := range sysmonWinEvents {
		if strings.Contains(ruleGroups, event) {
			mapping := map[string]string{
				// Process and executable info
				"data.win.eventdata.device":           "process.device",
				"data.win.eventdata.image":            "process.name",
				"data.win.eventdata.processId":        "process.pid",
				"data.win.system.processID":           "process.pid",
				"data.win.eventdata.commandLine":      "process.command_line",
				"data.win.eventdata.user":             "process.user",
				"data.win.eventdata.company":          "process.company",
				"data.win.eventdata.product":          "process.company_product",
				"data.win.eventdata.originalFileName": "process.dll.name",
				"data.win.eventdata.hashes":           "process.dll.hash",
				"data.win.eventdata.integrityLevel":   "process.integrity_level",
				"data.win.eventdata.currentDirectory": "process.cwd",
				"data.win.eventdata.logonId":          "process.logon_id",

				// DLL / module loading
				"data.win.eventdata.imageLoaded":     "process.dll.path",
				"data.win.eventdata.signature":       "process.dll.signature",
				"data.win.eventdata.signed":          "process.dll.signed",
				"data.win.eventdata.signatureStatus": "process.dll.signature_status",

				// Parent process
				"data.win.eventdata.parentImage":       "process.parent.name",
				"data.win.eventdata.parentProcessId":   "process.parent.pid",
				"data.win.eventdata.parentCommandLine": "process.parent.command_line",
				"data.win.eventdata.parentUser":        "process.parent.user",

				// Target / interaction fields
				"data.win.eventdata.targetObject":   "process.target_object",
				"data.win.eventdata.eventType":      "process.event",
				"data.win.eventdata.pipeName":       "process.pipe_name",
				"data.win.eventdata.targetFilename": "process.target_file_name",
				"data.win.eventdata.isExecutable":   "process.target_is_executable",

				// DNS / network activity
				"data.win.eventdata.queryName":       "process.dns.query",
				"data.win.eventdata.queryResults":    "process.dns.answer",
				"data.win.eventdata.queryStatus":     "process.dns.response_code",
				"data.win.eventdata.sourceIp":        "source.ip",
				"data.win.eventdata.sourcePort":      "source.port",
				"data.win.eventdata.destinationIp":   "destination.ip",
				"data.win.eventdata.destinationPort": "destination.port",
				"data.win.eventdata.protocol":        "network.protocol",

				// Access and tracing
				"data.win.eventdata.grantedAccess": "process.granted_access",
				"data.win.eventdata.callTrace":     "process.call_trace",
				"data.win.eventdata.sourceImage":   "process.source_image",
				"data.win.eventdata.targetImage":   "process.target_image",
			}
			raw = renameFields(raw, mapping)
			raw = setNetworkDirection(raw, initiated)
			raw = extractMitreInfo(raw, winMitre)
		}
	}
	return cleanFields(raw)
}
