package main

import "github.com/spf13/cobra"

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "bulwark",
		Short: "Bulwark — HTTP reverse-proxy auth gateway",
		// No action on bare invocation; print usage.
		SilenceUsage: true,
	}
	root.AddCommand(serveCmd())
	root.AddCommand(validateCmd())
	return root
}
