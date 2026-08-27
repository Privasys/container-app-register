// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package store

import "fmt"

// The register's base tables. Every one of them is ordinary ledger
// state: the root commits to the transaction log, the object heads, the
// record versions, the schemas, the policies and the keys alike.
//
// Constraints the SQL layer imposes, and how the register lives with
// them: every table declares a primary key; there are no foreign keys,
// so referential rules are enforced in the core (see the register
// package); there are no column defaults, so every INSERT names every
// column; and there is no DECIMAL, JSON or ENUM, so payloads travel as
// canonical JSON in BLOB columns and timestamps as Unix seconds.
var baseTables = []tableDDL{
	{
		name: "transactions",
		ddl: `CREATE TABLE ` + "`transactions`" + ` (
			seq BIGINT UNSIGNED PRIMARY KEY AUTO_INCREMENT,
			txid CHAR(64) NOT NULL,
			tenant VARCHAR(64) NOT NULL,
			kind VARCHAR(48) NOT NULL,
			class VARCHAR(64) NOT NULL,
			object_id VARCHAR(96) NOT NULL,
			author_sub VARCHAR(160) NOT NULL,
			author_display VARCHAR(160) NOT NULL,
			author_role VARCHAR(64) NOT NULL,
			summary VARCHAR(255) NOT NULL,
			created_at BIGINT NOT NULL,
			state VARCHAR(16) NOT NULL,
			root_before CHAR(64) NOT NULL,
			version_before BIGINT UNSIGNED NOT NULL,
			version_after BIGINT UNSIGNED NOT NULL,
			envelope BLOB NOT NULL,
			write_set BLOB NOT NULL
		)`,
		indexes: []string{
			"CREATE UNIQUE INDEX `tx_txid` ON `transactions` (txid)",
			"CREATE INDEX `tx_tenant_time` ON `transactions` (tenant, created_at)",
			"CREATE INDEX `tx_object` ON `transactions` (object_id, seq)",
			"CREATE INDEX `tx_state` ON `transactions` (state)",
			"CREATE INDEX `tx_author` ON `transactions` (author_sub)",
			"CREATE INDEX `tx_kind` ON `transactions` (kind)",
		},
	},
	{
		name: "tx_refs",
		ddl: `CREATE TABLE ` + "`tx_refs`" + ` (
			txid CHAR(64) NOT NULL,
			idx INT UNSIGNED NOT NULL,
			ref_type VARCHAR(24) NOT NULL,
			target VARCHAR(160) NOT NULL,
			PRIMARY KEY (txid, idx)
		)`,
		indexes: []string{
			"CREATE INDEX `ref_target` ON `tx_refs` (target)",
			"CREATE INDEX `ref_type` ON `tx_refs` (ref_type)",
		},
	},
	{
		name: "objects",
		ddl: `CREATE TABLE ` + "`objects`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			tenant VARCHAR(64) NOT NULL,
			class VARCHAR(64) NOT NULL,
			natural_key VARCHAR(191) NOT NULL,
			head_version BIGINT UNSIGNED NOT NULL,
			status VARCHAR(32) NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			created_tx CHAR(64) NOT NULL,
			updated_tx CHAR(64) NOT NULL,
			erased BOOLEAN NOT NULL
		)`,
		indexes: []string{
			"CREATE UNIQUE INDEX `obj_natural_key` ON `objects` (tenant, class, natural_key)",
			"CREATE INDEX `obj_class` ON `objects` (tenant, class, status)",
			"CREATE INDEX `obj_updated` ON `objects` (updated_at)",
		},
	},
	{
		// The natural-key index is what makes "this was never registered
		// here" provable. An absence proof is about one ledger key, so
		// the key a citizen actually asks about (a VIN, a plate) has to
		// be a key in its own right, not a column inside a row keyed by
		// something else.
		name: "natural_keys",
		ddl: `CREATE TABLE ` + "`natural_keys`" + ` (
			tenant VARCHAR(64) NOT NULL,
			class VARCHAR(64) NOT NULL,
			natural_key VARCHAR(191) NOT NULL,
			object_id VARCHAR(96) NOT NULL,
			updated_at BIGINT NOT NULL,
			PRIMARY KEY (tenant, class, natural_key)
		)`,
		indexes: []string{
			"CREATE INDEX `natkey_object` ON `natural_keys` (object_id)",
		},
	},
	{
		name: "record_versions",
		ddl: `CREATE TABLE ` + "`record_versions`" + ` (
			object_id VARCHAR(96) NOT NULL,
			version BIGINT UNSIGNED NOT NULL,
			txid CHAR(64) NOT NULL,
			schema_id VARCHAR(128) NOT NULL,
			created_at BIGINT NOT NULL,
			status VARCHAR(32) NOT NULL,
			payload_hash VARCHAR(96) NOT NULL,
			payload BLOB NOT NULL,
			enc_scope VARCHAR(191) NOT NULL,
			pruned BOOLEAN NOT NULL,
			prune_policy VARCHAR(64) NOT NULL,
			PRIMARY KEY (object_id, version)
		)`,
		indexes: []string{
			"CREATE INDEX `rec_txid` ON `record_versions` (txid)",
			"CREATE INDEX `rec_scope` ON `record_versions` (enc_scope)",
		},
	},
	{
		name: "schemas",
		ddl: `CREATE TABLE ` + "`schemas`" + ` (
			id VARCHAR(128) PRIMARY KEY,
			class VARCHAR(64) NOT NULL,
			version INT UNSIGNED NOT NULL,
			active BOOLEAN NOT NULL,
			doc BLOB NOT NULL,
			created_at BIGINT NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `schema_class` ON `schemas` (class, version)",
		},
	},
	{
		name: "policies",
		ddl: `CREATE TABLE ` + "`policies`" + ` (
			id VARCHAR(64) PRIMARY KEY,
			kind VARCHAR(32) NOT NULL,
			tenant VARCHAR(64) NOT NULL,
			class VARCHAR(64) NOT NULL,
			version INT UNSIGNED NOT NULL,
			active BOOLEAN NOT NULL,
			doc BLOB NOT NULL,
			created_at BIGINT NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `policy_scope` ON `policies` (tenant, class, kind)",
		},
	},
	{
		name: "tasks",
		ddl: `CREATE TABLE ` + "`tasks`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			tenant VARCHAR(64) NOT NULL,
			workflow VARCHAR(64) NOT NULL,
			class VARCHAR(64) NOT NULL,
			object_id VARCHAR(96) NOT NULL,
			state VARCHAR(24) NOT NULL,
			proposer_sub VARCHAR(160) NOT NULL,
			proposer_role VARCHAR(64) NOT NULL,
			counterparty VARCHAR(160) NOT NULL,
			counterparty_state VARCHAR(24) NOT NULL,
			payload BLOB NOT NULL,
			evidence BLOB NOT NULL,
			message VARCHAR(255) NOT NULL,
			created_at BIGINT NOT NULL,
			updated_at BIGINT NOT NULL,
			decided_by VARCHAR(160) NOT NULL,
			decided_at BIGINT NOT NULL,
			decision_reason VARCHAR(255) NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `task_state` ON `tasks` (tenant, state, updated_at)",
			"CREATE INDEX `task_object` ON `tasks` (object_id)",
			"CREATE INDEX `task_counterparty` ON `tasks` (counterparty, state)",
		},
	},
	{
		name: "keks",
		ddl: `CREATE TABLE ` + "`keks`" + ` (
			id VARCHAR(96) PRIMARY KEY,
			tenant VARCHAR(64) NOT NULL,
			algo VARCHAR(24) NOT NULL,
			public_key VARBINARY(1024) NOT NULL,
			enrolled_at BIGINT NOT NULL,
			active BOOLEAN NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `kek_tenant` ON `keks` (tenant, active)",
		},
	},
	{
		name: "dek_keys",
		ddl: `CREATE TABLE ` + "`dek_keys`" + ` (
			scope VARCHAR(191) PRIMARY KEY,
			tenant VARCHAR(64) NOT NULL,
			kind VARCHAR(32) NOT NULL,
			subject VARCHAR(96) NOT NULL,
			op_wrap VARBINARY(512) NOT NULL,
			rec_wrap VARBINARY(2048) NOT NULL,
			kek_id VARCHAR(96) NOT NULL,
			created_at BIGINT NOT NULL,
			destroyed_at BIGINT NOT NULL,
			txid CHAR(64) NOT NULL
		)`,
		indexes: []string{
			"CREATE INDEX `dek_subject` ON `dek_keys` (tenant, subject)",
		},
	},
	{
		name: "prune_marks",
		ddl: `CREATE TABLE ` + "`prune_marks`" + ` (
			txid CHAR(64) NOT NULL,
			idx INT UNSIGNED NOT NULL,
			object_id VARCHAR(96) NOT NULL,
			from_version BIGINT UNSIGNED NOT NULL,
			to_version BIGINT UNSIGNED NOT NULL,
			policy_id VARCHAR(64) NOT NULL,
			reason VARCHAR(64) NOT NULL,
			created_at BIGINT NOT NULL,
			PRIMARY KEY (txid, idx)
		)`,
		indexes: []string{
			"CREATE INDEX `prune_object` ON `prune_marks` (object_id, from_version)",
		},
	},
	{
		name: "webhooks",
		ddl: `CREATE TABLE ` + "`webhooks`" + ` (
			id VARCHAR(64) PRIMARY KEY,
			tenant VARCHAR(64) NOT NULL,
			url VARCHAR(255) NOT NULL,
			secret VARBINARY(128) NOT NULL,
			events VARCHAR(255) NOT NULL,
			txid CHAR(64) NOT NULL,
			active BOOLEAN NOT NULL,
			created_at BIGINT NOT NULL
		)`,
	},
	{
		name: "registry",
		ddl: `CREATE TABLE ` + "`registry`" + ` (
			k VARCHAR(96) PRIMARY KEY,
			v VARBINARY(4096) NOT NULL,
			updated_at BIGINT NOT NULL
		)`,
	},
}

type tableDDL struct {
	name    string
	ddl     string
	indexes []string
}

// Migrate creates any base table that does not exist yet. Creating a
// table is itself a ledger commit, so a fresh register's first
// transactions are the ones that bring its own catalogue into being.
func (s *Store) Migrate() error {
	return s.Do(func(tx *Tx) error {
		existing, err := tx.Tables()
		if err != nil {
			return err
		}
		for _, t := range baseTables {
			if existing[t.name] {
				continue
			}
			if err := tx.Exec(t.ddl); err != nil {
				return fmt.Errorf("store: create %s: %w", t.name, err)
			}
			for _, idx := range t.indexes {
				if err := tx.Exec(idx); err != nil {
					return fmt.Errorf("store: index on %s: %w", t.name, err)
				}
			}
		}
		return nil
	})
}
