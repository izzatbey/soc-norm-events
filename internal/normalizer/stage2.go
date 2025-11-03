package normalizer

import (
	"strings"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

func ApplyStage2Rules(raw string) string {
	decoder := gjson.Get(raw, "decoder.name").String()
}

func Event1(raw string) string {
	decoder := strings.ToLower(gjson.Get(raw, "decoder.name").String())
	ruleGroups := strings.ToLower(gjson.Get(raw, "rule.groups").String())

	
}