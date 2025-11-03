package main

import (
	"log"

	"github.com/izzatbey/soc-norm-events/internal/normalizer"
)

func main() {
	cfg := normalizer.Config{
		Brokers:     "localhost:9092",
		InputTopic:  "raw-logs",
		OutputTopic: "normalized-logs",
		GroupID:     "normalize-group",
	}

	if err := normalizer.Run(cfg); err != nil {
		log.Fatalf("❌ Normalizer exited: %v", err)
	}
}
