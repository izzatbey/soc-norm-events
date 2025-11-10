package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func ApplyStage4Rules(raw string) string {
	// Drop Fluent Bit or internal noise logs early
	// programName := strings.ToLower(gjson.Get(raw, "predecoder.program_name").String())
	// if programName == "fluent-bit" {
	// 	return ""
	// }
	raw = NginxRemap(raw)
	raw = NginxDomainRules(raw)
	return raw
}

func NginxRemap(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	location := strings.ToLower(gjson.Get(raw, "location").String())

	if !(strings.Contains(decoder, "web-accesslog") && strings.Contains(location, "nginx")) {
		return raw
	}

	mapping := map[string]string{
		"data.srcip":    "source.ip",
		"data.protocol": "http.request.method",
		"data.id":       "http.response.status_code",
		"data.url":      "url.path",
	}
	raw = renameFields(raw, mapping)
	return raw
}

func NginxDomainRules(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	if !strings.Contains(decoder, "web-accesslog") {
		return raw
	}

	location := gjson.Get(raw, "location").String()
	agent := gjson.Get(raw, "agent.name").String()

	switch {
	case location == "/var/log/nginx/api-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "api.esign.id")
	case location == "/var/log/nginx/apionprem-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "apionprem.mesign.id")
	case location == "/var/log/nginx/apira-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "apira.mesign.id")
	case location == "/var/log/nginx/apisigning-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "apisigning.mesign.id")
	case location == "/var/log/nginx/app-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "app.esign.id")
	case location == "/var/log/nginx/app-ez-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "app.ezsign.id")
	case location == "/var/log/nginx/app-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "app.mesign.id")
	case location == "/var/log/nginx/appra-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "appra.mesign.id")
	case location == "/var/log/nginx/config-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "config.mesign.id")
	case location == "/var/log/nginx/csirt-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "csirt.esign.id")
	case location == "/var/log/nginx/dev-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "devapi.mesign.id")
	case location == "/var/log/nginx/docrepo-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "docrepo.mesign.id")
	case location == "/var/log/nginx/esign-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "esign.id")
	case location == "/var/log/nginx/ez-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "ezsign.id")
	case location == "/var/log/nginx/jtp-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "jtp.esign.id")
	case location == "/var/log/nginx/mesign-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "mesign.id")
	case location == "/var/log/nginx/stag-nginx-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "nginx.mesign.id")
	case location == "/var/log/nginx/repository-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "repository.esign.id")
	case location == "/var/log/nginx/repository-ez-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "repository.ezsign.id")
	case location == "/var/log/nginx/repository-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "repository.mesign.id")
	case location == "/var/log/nginx/sig-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "sig.esign.id")
	case location == "/var/log/nginx/signcrl-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "signcrl.esign.id")
	case location == "/var/log/nginx/signcrl-ez-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "signcrl.ezsign.id")
	case location == "/var/log/nginx/signcrl-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "signcrl.mesign.id")
	case location == "/var/log/nginx/signoscp-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "signoscp.esign.id")
	case location == "/var/log/nginx/signoscp-ez-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "signoscp.ezsign.id")
	case location == "/var/log/nginx/signoscp-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "signoscp.mesign.id")
	case location == "/var/log/nginx/signtest-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "signtest.esign.id")
	case location == "/var/log/nginx/tsa-access.raw.log" && strings.Contains(agent, "nginx-stagging"):
		raw, _ = sjson.Set(raw, "url.domain", "tsa.mesign.id")
	case location == "/var/log/nginx/www-esign-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "www.esign.id")
	case location == "/var/log/nginx/www-ez-access.raw.log" && strings.Contains(agent, "nginx-ex"):
		raw, _ = sjson.Set(raw, "url.domain", "www.ezsign.id")
	}

	return raw
}
