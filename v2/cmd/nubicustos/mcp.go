package main

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"

	"github.com/Su1ph3r/nubicustos/internal/mcp"
	"github.com/Su1ph3r/nubicustos/internal/store"
)

type mcpFlags struct {
	dbPath string
}

func newMCPCmd() *cobra.Command {
	f := &mcpFlags{}
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve scan results to an LLM over the Model Context Protocol (stdio)",
		Long: "Run a Model Context Protocol server over stdio, exposing read-only tools to\n" +
			"query stored scans, findings, and attack paths. It performs no cloud calls\n" +
			"and never triggers a scan — it reads the local results database.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMCP(cmd.Context(), f)
		},
	}
	cmd.Flags().StringVar(&f.dbPath, "db", "nubicustos.db", "path to the SQLite results database")
	return cmd
}

func runMCP(ctx context.Context, f *mcpFlags) error {
	st, err := store.Open(ctx, f.dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	srv := mcp.NewServer(st, version)
	if err := server.ServeStdio(srv); err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	return nil
}
