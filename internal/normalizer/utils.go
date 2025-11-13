package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func extractMitreInfo(raw string, ruleName string) string {

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

func cleanFields(raw string) string {
	dropList := []string{
		"data.devname",
		"data.eventdata.company",
		"data.eventdata.description",
		"data.eventdata.fileVersion",
		"data.eventdata.product",
		"data.eventdata.originalFileName",
		"data.eventdata.integrityLevel",
		"data.eventdata.parentProcessGuid",
		"data.eventdata.processGuid",
		"data.eventtime",
		"data.level",
		"data.logid",
		"data.rcvdpkt",
		"data.sentpkt",
		"data.system.keywords",
		"data.system.opcode",
		"data.system.task",
		"data.system.eventRecordID",
		"data.system.processID",
		"data.system.threadID",
		"data.system.systemTime",
		"data.system.version",
		"data.time",
		"data.trandisp",
		"data.detail",
		"data.message",
		"data.backend_type",
		"data.line_num",
		"data.query_id",
		"data.txid",
		"data.vxid",
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
		"data.win.system.eventID",
		"data.win.system.level",
		"data.win.system.systemTime",
		"data.win.system.providerGuid",
		"data.win.system.providerName",
		"data.win.eventdata.ruleName",
		"data.win.eventdata.utcTime",
		"process.company",
		"predecoder.hostname",
		"rule.mail",
		"rule.firedtimes",
		"time",
	}
	sections := []string{
		"data.eventdata", "data.system", "process", "process.parent", "file", "data",
	}

	nullValues := []string{"", "-", "null", "N/A"}

	for _, key := range dropList {
		if gjson.Get(raw, key).Exists() {
			raw, _ = sjson.Delete(raw, key)
		}
	}

	for _, section := range sections {
		obj := gjson.Get(raw, section)
		if obj.Exists() && obj.IsObject() {
			for k, v := range obj.Map() {
				strVal := strings.TrimSpace(v.String())
				for _, nv := range nullValues {
					if strings.EqualFold(strVal, nv) {
						raw, _ = sjson.Delete(raw, section+"."+k)
						break
					}
				}
			}
		}
	}

	return raw
}

func setNetworkDirection(raw, initiated string) string {
	initiated = strings.ToLower(strings.TrimSpace(initiated))

	switch {
	case strings.Contains(initiated, "true"):
		raw, _ = sjson.Set(raw, "network.direction", "egress")
	case strings.Contains(initiated, "false"):
		raw, _ = sjson.Set(raw, "network.direction", "ingress")
	}

	return raw
}
