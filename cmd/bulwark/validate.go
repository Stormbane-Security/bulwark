package main

import (
	"fmt"

	"github.com/patrickputman/bulwark/internal/config"
	"github.com/spf13/cobra"
)

func validateCmd() *cobra.Command {
	var configPath string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a Bulwark configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if configPath == "" {
				return fmt.Errorf("--config is required")
			}
			_, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}
			fmt.Println("config ok")
			return nil
		},
	}

	cmd.Flags().StringVar(&configPath, "config", "", "path to bulwark.yaml")
	return cmd
}
