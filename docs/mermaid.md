flowchart TD
  %% --- Entry / orchestration ---
  CLI["CLI / Scheduler\n(runner.py)"] --> RC["Build RunContext\n(tenant/workspace/run_id/run_ts)\n+ inject Services (AWS SDK clients)"]

  %% --- Checker execution ---
  RC --> DISC["Checker selection\n(default: all)\n(optional: include/exclude)"]
  DISC --> CHK["Run checkers\n(checks/*)\nEmit FindingDraft (wire)"]

  %% --- Contract boundary ---
  CHK --> VAL["Contract validation\n(contracts/*)\n- required fields\n- enums/coherence\n- compute fingerprint\n- compute finding_id"]

  %% --- Storage boundary ---
  VAL --> CAST["Storage cast\n(contracts/storage_cast.py)\nwire -> typed record\n(Arrow schema)"]

  %% --- Persistence ---
  CAST --> PQ["Parquet dataset\n(pipeline/writer_parquet.py)\npartitioned by tenant + date"]

  %% --- Analytics / export ---
  PQ --> DDB["DuckDB queries\n(pipeline/*)\nread Parquet directly"]
  DDB --> JSON["JSON exports\n(pipeline/export_json.py)\nfor UI / API"]

  %% --- UI / API ---
  JSON --> UI["Flask UI / API\n(consumer)"]

  %% --- Optional / near-future blocks ---
  subgraph Future["Near-future product primitives"]
    STATE["Finding state store\n(Postgres)\nack/snooze/owner/notes"] 
    CUR["CUR / Billing facts\n(Parquet/Iceberg)\nactuals + allocation"]
  end

  %% Joining state and cost
  PQ -. "join by fingerprint" .-> STATE
  DDB -. "join actuals" .-> CUR
  CUR -. "enrich exports" .-> JSON
  STATE -. "enrich exports" .-> JSON
