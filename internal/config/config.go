package config

import (
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Brokers     string
	InputTopic  string
	OutputTopic string
	GroupID     string
}

func Load() *Config {
	v := viper.New()

	v.SetDefault("KAFKA_BROKER", "localhost:9092")
	v.SetDefault("KAFKA_INPUT_TOPIC", "input-topic")
	v.SetDefault("KAFKA_OUTPUT_TOPIC", "output-topic")
	v.SetDefault("KAFKA_GROUP_ID", "normalizer-group")

	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	return &Config{
		Brokers:     v.GetString("KAFKA_BROKER"),
		InputTopic:  v.GetString("KAFKA_INPUT_TOPIC"),
		OutputTopic: v.GetString("KAFKA_OUTPUT_TOPIC"),
		GroupID:     v.GetString("KAFKA_GROUP_ID"),
	}
}
