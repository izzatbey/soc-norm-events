package normalizer

import (
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func nginxRemap(raw string) string {
	mapping := map[string]string{
		"data.srcip":    "source.ip",
		"data.protocol": "http.request.method",
		"data.id":       "http.response.status_code",
		"data.url":      "url.path",
	}
	raw = renameFields(raw, mapping)
	raw = nginxDomainRules(raw)

	return raw
}

func nginxDomainRules(raw string) string {
	location := gjson.Get(raw, "location").String()
	agent := gjson.Get(raw, "agent.name").String()

	locationDomainMap := map[string]map[string]string{
		"/var/log/nginx/api-access.raw.log": {
			"nginx-ex": "api.esign.id",
		},
		"/var/log/nginx/apionprem-access.raw.log": {
			"nginx-stagging": "apionprem.mesign.id",
		},
		"/var/log/nginx/apira-access.raw.log": {
			"nginx-stagging": "apira.mesign.id",
		},
		"/var/log/nginx/apisigning-access.raw.log": {
			"nginx-stagging": "apisigning.mesign.id",
		},
		"/var/log/nginx/app-access.raw.log": {
			"nginx-ex":       "app.esign.id",
			"nginx-stagging": "app.mesign.id",
		},
		"/var/log/nginx/app-ez-access.raw.log": {
			"nginx-ex": "app.ezsign.id",
		},
		"/var/log/nginx/appra-access.raw.log": {
			"nginx-stagging": "appra.mesign.id",
		},
		"/var/log/nginx/config-access.raw.log": {
			"nginx-stagging": "config.mesign.id",
		},
		"/var/log/nginx/csirt-access.raw.log": {
			"nginx-ex": "csirt.esign.id",
		},
		"/var/log/nginx/dev-access.raw.log": {
			"nginx-stagging": "devapi.mesign.id",
		},
		"/var/log/nginx/docrepo-access.raw.log": {
			"nginx-stagging": "docrepo.mesign.id",
		},
		"/var/log/nginx/esign-access.raw.log": {
			"nginx-ex": "esign.id",
		},
		"/var/log/nginx/ez-access.raw.log": {
			"nginx-ex": "ezsign.id",
		},
		"/var/log/nginx/jtp-access.raw.log": {
			"nginx-ex": "jtp.esign.id",
		},
		"/var/log/nginx/mesign-access.raw.log": {
			"nginx-stagging": "mesign.id",
		},
		"/var/log/nginx/stag-nginx-access.raw.log": {
			"nginx-stagging": "nginx.mesign.id",
		},
		"/var/log/nginx/repository-access.raw.log": {
			"nginx-ex":       "repository.esign.id",
			"nginx-stagging": "repository.mesign.id",
		},
		"/var/log/nginx/repository-ez-access.raw.log": {
			"nginx-ex": "repository.ezsign.id",
		},
		"/var/log/nginx/sig-access.raw.log": {
			"nginx-ex": "sig.esign.id",
		},
		"/var/log/nginx/signcrl-access.raw.log": {
			"nginx-ex":       "signcrl.esign.id",
			"nginx-stagging": "signcrl.mesign.id",
		},
		"/var/log/nginx/signcrl-ez-access.raw.log": {
			"nginx-ex": "signcrl.ezsign.id",
		},
		"/var/log/nginx/signoscp-access.raw.log": {
			"nginx-ex":       "signoscp.esign.id",
			"nginx-stagging": "signoscp.mesign.id",
		},
		"/var/log/nginx/signoscp-ez-access.raw.log": {
			"nginx-ex": "signoscp.ezsign.id",
		},
		"/var/log/nginx/signtest-access.raw.log": {
			"nginx-ex": "signtest.esign.id",
		},
		"/var/log/nginx/tsa-access.raw.log": {
			"nginx-stagging": "tsa.mesign.id",
		},
		"/var/log/nginx/www-esign-access.raw.log": {
			"nginx-ex": "www.esign.id",
		},
		"/var/log/nginx/www-ez-access.raw.log": {
			"nginx-ex": "www.ezsign.id",
		},
	}

	if domains, ok := locationDomainMap[location]; ok {
		for key, domain := range domains {
			if strings.Contains(agent, key) {
				raw, _ = sjson.Set(raw, "url.domain", domain)
				break
			}
		}
	}

	return raw
}
