package main

import (
	"log"

	"github.com/izzatbey/soc-norm-events/internal/normalizer"
	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the normalizer server",
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("Starting Normalizer")
		if err := normalizer.Run(cfg); err != nil {
			log.Fatalf("❌ normalizer error: %v", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(serverCmd)
}
