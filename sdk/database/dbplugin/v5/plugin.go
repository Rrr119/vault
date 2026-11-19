// Copyright IBM Corp. 2016, 2026
// SPDX-License-Identifier: MPL-2.0

package dbplugin

// Plugin is the contract implemented by a database secrets engine plugin.
//
// Vault calls Initialize once per database connection, then uses NewUser,
// UpdateUser, and DeleteUser to manage dynamic and static database accounts.
// Implementations are served with Serve or ServeMultiplex and registered in
// Vault's plugin catalog with the "database" plugin type.
type Plugin = Database
