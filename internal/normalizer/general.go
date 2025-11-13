package normalizer

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func standardizeEvent(raw string) string {
	for src, dst := range normalizationMap {
		if v := gjson.Get(raw, src); v.Exists() {
			raw, _ = sjson.Set(raw, dst, v.Value())
		}
	}

	raw = sanitizePostgresLogs(raw)
	raw = addWazuhLogID(raw)
	raw = cleanFields(raw)
	return raw
}

var normalizationMap = map[string]string{
	// Source / Destination IPs
	"data.srcip":                       "source.ip",
	"data.win.eventdata.sourceIp":      "source.ip",
	"data.eventdata.sourceIp":          "source.ip",
	"data.dstip":                       "destination.ip",
	"data.win.eventdata.destinationIp": "destination.ip",
	"data.eventdata.DestinationIp":     "destination.ip",

	// Hashes
	"syscheck.sha1_after":       "file.hash.sha1",
	"syscheck.sha256_after":     "file.hash.sha256",
	"syscheck.md5_after":        "file.hash.md5",
	"data.win.eventdata.hash":   "file.hash.combined",
	"data.win.eventdata.hashes": "file.hash.combined",

	// Hostnames / DNS
	"data.dst_host":                          "destination.domain",
	"data.win.eventdata.destinationHostname": "destination.domain",
	"data.win.eventdata.queryName":           "dns.question.name",

	// Network Interfaces
	"data.netinfo.iface.mac":      "observer.mac",
	"data.netinfo.iface.name":     "observer.name",
	"data.netinfo.iface.rx_bytes": "network.ingress.bytes",
	"data.netinfo.iface.tx_bytes": "network.egress.bytes",

	// Network Metadata
	"data.sentbyte":      "network.egress.bytes",
	"data.rcvdbyte":      "network.ingress.bytes",
	"data.session_start": "event.start",

	// Ports
	"data.port.local_port":  "source.port",
	"data.port.remote_port": "destination.port",

	// Protocols
	"data.proto":     "network.protocol",
	"data.transport": "network.transport",

	// Processes
	"data.process.name": "process.name",

	// Users
	"data.process.euser":                 "user.name",
	"data.win.eventdata.user":            "user.name",
	"data.win.eventdata.subjectUserName": "user.name",
	"data.audit.acct":                    "user.name",
	"data.audit.user":                    "user.name",
}

func sanitizePostgresLogs(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	location := strings.ToLower(gjson.Get(raw, "location").String())

	if strings.Contains(decoder, "json") && strings.Contains(location, "postgresql") {
		dropFields := []string{
			"data.detail",
			"data.message",
			"data.backend_type",
			"data.line_num",
			"data.query_id",
			"data.txid",
			"data.vxid",
		}
		for _, key := range dropFields {
			if gjson.Get(raw, key).Exists() {
				raw, _ = sjson.Delete(raw, key)
			}
		}
	}
	return raw
}

func addWazuhLogID(raw string) string {
	inputID := gjson.Get(raw, "id").String()
	if inputID == "" {
		return raw
	}

	agentName := gjson.Get(raw, "agent.name").String()
	timestamp := gjson.Get(raw, "timestamp").String()

	hashInput := agentName + timestamp
	h := sha1.Sum([]byte(hashInput))
	hashValue := hex.EncodeToString(h[:])

	newRaw, _ := sjson.Set(raw, "wazuh.log.id", hashValue)
	return newRaw
}
