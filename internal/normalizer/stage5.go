package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ============================
//
//	ApplyStage5Rules
//
// ============================
func ApplyStage5Rules(raw string) string {
	// Drop Fluent Bit self-generated logs
	if strings.ToLower(gjson.Get(raw, "predecoder.program_name").String()) == "fluent-bit" {
		return ""
	}

	raw = normalizeSourceIP(raw)
	raw = normalizeDestinationIP(raw)
	raw = normalizeHashes(raw)
	raw = normalizeHostnames(raw)
	raw = normalizeInterfaces(raw)
	raw = normalizeNetworkMetadata(raw)
	raw = normalizePorts(raw)
	raw = normalizeProtocols(raw)
	raw = normalizeProcesses(raw)
	raw = normalizeUsers(raw)
	raw = sanitizePostgresLogs(raw)
	raw = cleanupEmptyFields(raw)
	return raw
}

//
// ============================
//  Generic Normalization Rules
// ============================
//

// --- Source IP ---
func normalizeSourceIP(raw string) string {
	aliases := []string{
		"data.srcip",
		"data.win.eventdata.sourceIp",
		"data.eventdata.sourceIp",
	}
	for _, field := range aliases {
		if v := gjson.Get(raw, field); v.Exists() {
			raw, _ = sjson.Set(raw, "source.ip", v.Value())
			break
		}
	}
	return raw
}

// --- Destination IP ---
func normalizeDestinationIP(raw string) string {
	aliases := []string{
		"data.dstip",
		"data.win.eventdata.destinationIp",
		"data.eventdata.DestinationIp",
	}
	for _, field := range aliases {
		if v := gjson.Get(raw, field); v.Exists() {
			raw, _ = sjson.Set(raw, "destination.ip", v.Value())
			break
		}
	}
	return raw
}

// --- Hashes (MD5, SHA1, SHA256) ---
func normalizeHashes(raw string) string {
	mapping := map[string]string{
		"syscheck.sha1_after":       "file.hash.sha1",
		"syscheck.sha256_after":     "file.hash.sha256",
		"syscheck.md5_after":        "file.hash.md5",
		"data.win.eventdata.hash":   "file.hash.combined",
		"data.win.eventdata.hashes": "file.hash.combined",
		"data.eventdata.hashes":     "file.hash.combined",
	}
	for old, new := range mapping {
		if v := gjson.Get(raw, old); v.Exists() {
			raw, _ = sjson.Set(raw, new, v.Value())
		}
	}
	return raw
}

// --- Hostnames / DNS ---
func normalizeHostnames(raw string) string {
	if v := gjson.Get(raw, "data_dst_host"); v.Exists() {
		raw, _ = sjson.Set(raw, "destination.domain", v.Value())
	}
	if v := gjson.Get(raw, "data_win_eventdata_destinationHostname"); v.Exists() {
		raw, _ = sjson.Set(raw, "destination.domain", v.Value())
	}
	if v := gjson.Get(raw, "data_win_eventdata_queryName"); v.Exists() {
		raw, _ = sjson.Set(raw, "dns.question.name", v.Value())
	}
	return raw
}

// --- Network Interfaces ---
func normalizeInterfaces(raw string) string {
	mapping := map[string]string{
		"data.netinfo.iface.mac":      "observer.mac",
		"data.netinfo.iface.name":     "observer.name",
		"data.netinfo.iface.rx_bytes": "network.ingress.bytes",
		"data.netinfo.iface.tx_bytes": "network.egress.bytes",
	}
	for old, new := range mapping {
		if v := gjson.Get(raw, old); v.Exists() {
			raw, _ = sjson.Set(raw, new, v.Value())
		}
	}
	return raw
}

// --- Network Metadata (flow byte counts / timestamps) ---
func normalizeNetworkMetadata(raw string) string {
	mapping := map[string]string{
		"data.sentbyte":      "network.egress.bytes",
		"data.rcvdbyte":      "network.ingress.bytes",
		"data.session_start": "event.start",
	}
	for old, new := range mapping {
		if v := gjson.Get(raw, old); v.Exists() {
			raw, _ = sjson.Set(raw, new, v.Value())
		}
	}
	return raw
}

// --- Ports ---
func normalizePorts(raw string) string {
	mapping := map[string]string{
		"data.srcport":          "source.port",
		"data.dstport":          "destination.port",
		"data.port.local_port":  "source.port",
		"data.port.remote_port": "destination.port",
	}
	for old, new := range mapping {
		if v := gjson.Get(raw, old); v.Exists() {
			raw, _ = sjson.Set(raw, new, v.Value())
		}
	}
	return raw
}

// --- Protocols ---
func normalizeProtocols(raw string) string {
	mapping := map[string]string{
		"data.proto":                  "network.protocol",
		"data.transport":              "network.transport",
		"data.win.eventdata.protocol": "network.protocol",
	}
	for old, new := range mapping {
		if v := gjson.Get(raw, old); v.Exists() {
			raw, _ = sjson.Set(raw, new, v.Value())
		}
	}
	return raw
}

// --- Processes ---
func normalizeProcesses(raw string) string {
	if v := gjson.Get(raw, "data.process.name"); v.Exists() {
		raw, _ = sjson.Set(raw, "process.name", v.Value())
	}
	return raw
}

// --- Users ---
func normalizeUsers(raw string) string {
	userFields := []string{
		"data.process.euser",
		"data.win.eventdata.user",
		"data.win.eventdata.subjectUserName",
		"data.audit.acct",
		"data.audit.user",
	}
	for _, field := range userFields {
		if v := gjson.Get(raw, field); v.Exists() {
			raw, _ = sjson.Set(raw, "user.name", v.Value())
			break
		}
	}
	return raw
}

func sanitizePostgresLogs(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	location := strings.ToLower(gjson.Get(raw, "location").String())

	// Match PostgreSQL JSON logs
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

func cleanupEmptyFields(raw string) string {
	sections := []string{
		"source", "destination", "network", "observer",
		"user", "file.hash", "process",
	}

	for _, section := range sections {
		obj := gjson.Get(raw, section)
		if obj.Exists() && obj.IsObject() {
			for k, v := range obj.Map() {
				str := strings.TrimSpace(v.String())
				if str == "" || str == "-" || strings.EqualFold(str, "null") {
					raw, _ = sjson.Delete(raw, section+"."+k)
				}
			}
		}
	}
	return raw
}
