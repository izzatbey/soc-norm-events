package main

import (
	"fmt"
	"os"

	"github.com/izzatbey/soc-norm-events/internal/config"
	"github.com/spf13/cobra"
)

var cfg *config.Config

var rootCmd = &cobra.Command{
	Use:   "normalizer",
	Short: "SOC Event Normalizer",
	Long:  `A Kafka consumer-producer that normalizes SOC event logs.`,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	cfg = config.Load()
}
