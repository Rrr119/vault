// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/plugins/database/example"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func main() {
	if err := Run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Run starts the database plugin RPC server.
func Run() error {
	dbplugin.ServeMultiplex(example.New)
	return nil
}
