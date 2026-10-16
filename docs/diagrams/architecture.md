# Pentest Bot T800 — Architecture

High-level layout of the AI-driven pentest orchestrator: entry surfaces, the agentic scan loop, persistence, and how findings flow into reports and the attack-surface graph.

## System Context

Who talks to the bot, and what external systems it depends on.

```mermaid
flowchart LR
  operator["Operator"] --> cli["CLI / Interactive REPL"]
  cli --> orchestrator["Orchestrator"]
  cli --> assistant["Assistant chat"]
  orchestrator --> planner["AI Planner"]
  assistant --> llm["LLM API"]
  planner --> llm
  orchestrator --> scanners["Scanner tools"]
  assistant --> toolRouter["Tool router"]
  toolRouter --> sqlite["SQLite"]
  toolRouter --> neo4j["Neo4j graph"]
  toolRouter --> scanners
  orchestrator --> sqlite
  orchestrator --> neo4j
  orchestrator --> reports["HTML / JSON reports"]
  scanners --> nmap["nmap"]
  scanners --> zap["OWASP ZAP"]
  scanners --> fuzzers["ffuf / feroxbuster / nuclei"]
  scanners --> intel["Shodan / NVD"]
  scanners --> cloud["prowler / cloudflair"]
```

## Component Map

Internal packages and how they collaborate during a run.

```mermaid
flowchart TB
  subgraph entry [Entry]
    mainEntry["__main__"]
    cliMod["cli"]
  end

  subgraph core [Core control plane]
    orch["orchestrator"]
    scope["ScopeGuard"]
    jobs["JobManager"]
    session["SessionManager"]
  end

  subgraph aiLayer [AI layer]
    plannerMod["Planner"]
    recovery["FailureRecovery"]
    assistantMod["Assistant"]
    router["tool_router"]
    client["AIClient"]
    summarizer["summarizer"]
    cvss["CVSS scorer"]
  end

  subgraph tools [Tool adapters]
    schema["ToolResult / ScanState"]
    rateGuard["RateLimitDetector"]
    cache["ToolResultCache"]
    adapters["nmap zap ffuf nuclei sqlmap ..."]
  end

  subgraph data [Persistence and output]
    db["SQLite DB"]
    evo["EvoGraph lessons"]
    graph["GraphDB Neo4j"]
    reporting["normalize + render"]
  end

  mainEntry --> cliMod
  cliMod --> orch
  cliMod --> assistantMod
  cliMod --> session
  orch --> scope
  orch --> plannerMod
  orch --> recovery
  orch --> jobs
  orch --> adapters
  orch --> rateGuard
  orch --> cache
  orch --> db
  orch --> evo
  orch --> graph
  orch --> summarizer
  orch --> cvss
  orch --> reporting
  plannerMod --> client
  assistantMod --> client
  assistantMod --> router
  router --> db
  router --> graph
  router --> jobs
  adapters --> schema
```

## Agentic Scan Flow

Mandatory recon, then plan → execute → learn until done, followed by scoring and reporting.

```mermaid
flowchart TD
  start["Start agentic scan"] --> scopeCheck["Enforce scope"]
  scopeCheck --> createRun["Create run record and workdir"]
  createRun --> phase1["Phase 1: nmap recon"]
  phase1 --> waf["WAF detect and optional origin discovery"]
  waf --> httpx["Confirm live HTTP endpoints"]
  httpx --> shodan["Shodan intelligence"]
  shodan --> loadLessons["Inject EvoGraph lessons"]
  loadLessons --> planLoop{"Planner next action"}
  planLoop -->|done| score["CVSS score findings"]
  planLoop -->|scatter| parallel["Run safe tools in parallel"]
  planLoop -->|single| approve{"Needs approval?"}
  approve -->|declined| planLoop
  approve -->|ok| dispatch["Dispatch tool under rate guard"]
  parallel --> persist["Persist findings, graph, lessons"]
  dispatch --> persist
  persist --> planLoop
  score --> summarize["Summarize run"]
  summarize --> report["Write report and finish run"]
```

## Persistence Model

SQLite is the system of record; Neo4j is an optional attack-surface mirror.

```mermaid
erDiagram
  runs ||--o{ findings : contains
  runs ||--o{ artifacts : stores
  runs ||--o{ audit_log : audits
  sessions ||--o{ assistant_messages : history
  runs ||--o{ assistant_messages : context
  runs ||--o{ evograph_events : lessons

  runs {
    int id
    string target
    string status
    string summary
  }
  findings {
    int id
    string source
    string severity
    string owasp
    float cvss_score
  }
  artifacts {
    int id
    string tool
    string path
  }
  sessions {
    string id
  }
  evograph_events {
    string event_type
    string target
    string tool
    string lesson
  }
```

## Attack Surface Graph

Optional Neo4j shape synced after each tool result.

```mermaid
flowchart LR
  host["Host"] --> port["Port"]
  host --> service["Service"]
  host --> urlNode["URL"]
  host --> vuln["Vulnerability"]
  host --> runNode["Run"]
  vuln --> runNode
```
