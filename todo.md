# Dang! — Project TODO

## Phase 2: Theme & Dependencies
- [x] Apply Amethyst Nexus theme to index.css
- [x] Update index.html with Google Fonts and dark class
- [x] Install recharts, date-fns, framer-motion (already in deps)
- [x] Update App.tsx with dark ThemeProvider and route structure

## Phase 3: Backend — Wazuh Proxy
- [x] Add Wazuh credentials to secrets (WAZUH_HOST, WAZUH_USER, WAZUH_PASS)
- [x] Create server/wazuh/wazuhClient.ts — proxy client with auth, rate limiting, field filtering
- [x] Create server/wazuh/wazuhRouter.ts — tRPC router with all GET endpoints
- [x] Implement /agents, /agents/summary, /agents/status endpoints
- [x] Implement /alerts (via manager logs/stats) endpoints
- [x] Implement /vulnerabilities endpoints
- [x] Implement /mitre endpoints (tactics, techniques, groups, metadata)
- [x] Implement /sca (compliance) endpoints
- [x] Implement /syscheck (FIM) endpoints
- [x] Implement /ciscat endpoints
- [x] Register wazuh router in server/routers.ts

## Phase 4: Backend — HybridRAG + Analyst Notes
- [x] Add analyst_notes and rag_sessions tables to drizzle/schema.ts
- [x] Run migration for analyst_notes and rag_sessions
- [x] Create server/hybridrag/hybridragRouter.ts — Nemotron 3 Nano integration
- [x] Implement RAG context building from Wazuh telemetry
- [x] Implement chat endpoint with fallback LLM
- [x] Implement analyst notes CRUD (create, list, getById, update, delete)
- [x] Register hybridrag router in server/routers.ts

## Phase 5: Frontend — Layout & Shared Components
- [x] Read and customize DashboardLayout.tsx for Amethyst Nexus
- [x] Build GlassPanel shared component
- [x] Build ThreatBadge severity badge component
- [x] Build StatCard metric card component
- [x] Build RefreshControl component
- [x] Build RawJsonViewer component
- [x] Build PageHeader component
- [x] Build WazuhGuard connection guard component
- [x] Update App.tsx with all 9 routes
- [x] Update sidebar navigation items

## Phase 6: Agent Health Dashboard
- [x] Create client/src/pages/AgentHealth.tsx
- [x] Agent status overview cards (active/disconnected/never connected)
- [x] OS distribution donut chart
- [x] Agent list table with search/filter
- [x] Configurable auto-refresh

## Phase 7: Alerts Timeline + MITRE ATT&CK
- [x] Create client/src/pages/AlertsTimeline.tsx
- [x] Severity filter controls
- [x] Hourly event distribution bar chart
- [x] Weekly heatmap (day × hour)
- [x] Manager logs table with pagination
- [x] Create client/src/pages/MitreAttack.tsx
- [x] Tactic columns (ATT&CK matrix style)
- [x] Technique cards with descriptions
- [x] Threat groups section

## Phase 8: Vulnerabilities + FIM
- [x] Create client/src/pages/Vulnerabilities.tsx
- [x] CVE severity distribution pie chart
- [x] Status breakdown bar chart
- [x] CVE detail table with pagination
- [x] Create client/src/pages/FileIntegrity.tsx
- [x] Last scan status cards
- [x] Syscheck files table with hash display
- [x] File path search filter

## Phase 9: Compliance Posture + Analyst Notes
- [x] Create client/src/pages/Compliance.tsx
- [x] SCA policy cards with compliance scores
- [x] Compliance score horizontal bar chart
- [x] Policy checks table (pass/fail)
- [x] Create client/src/pages/AnalystNotes.tsx
- [x] Note creation dialog with severity, agent ID, rule ID, CVE ID
- [x] Notes list with resolve/delete actions
- [x] Severity filter

## Phase 10: HybridRAG Assistant Panel
- [x] Create client/src/pages/Assistant.tsx
- [x] Chat interface with message history
- [x] Suggestion chips for common queries
- [x] Model status indicator (Nemotron vs Fallback)
- [x] Session clear functionality
- [x] Wazuh context injection toggle
- [x] Wire configurable refresh intervals across all pages

## Phase 11: Tests & QA
- [x] Write vitest tests for wazuh proxy router
- [x] Write vitest tests for hybridrag router (model status, notes CRUD)
- [x] All 6 tests passing
- [x] TypeScript compilation clean (0 errors)
- [x] Final integration check — all pages render correctly
- [x] Save checkpoint

## Phase 12: Dashboard Rebuild — Backend Expansion
- [x] Add syscollector endpoints (hardware, os, packages, ports, processes, browser_extensions, services, users/groups)
- [x] Add manager stats endpoints (stats, stats/hourly, daemons/stats, configuration/validation)
- [x] Add cluster endpoints (status, nodes, health)
- [x] Add Indexer API proxy (via Server API endpoints) for wazuh-alerts-*, wazuh-states-vulnerabilities-* queries

## Phase 13: SOC Console (Security Overview Rebuild)
- [x] Events Per Second (EPS) gauge with capacity indicator
- [x] Threat Trends area chart (rule.level × timestamp)
- [x] Top Talkers pie chart (agents by alert count)
- [x] MITRE ATT&CK tactic distribution bar chart
- [x] Alert severity distribution donut
- [x] Recent critical alerts table
- [x] Manager status indicators

## Phase 14: Fleet Command Center (Agent Health Rebuild)
- [x] Agent KPI cards (total, active, disconnected, never connected, pending)
- [x] OS distribution donut chart
- [x] Agent version distribution bar chart
- [x] Agent detail drawer with syscollector data
- [x] Agent group management view
- [x] Connection stability timeline (via last keep alive)
- [x] Agent search/filter with multi-column sort

## Phase 15: IT Hygiene Ecosystem (New Page)
- [ ] Three-column layout: Extensions | Services | Identity
- [ ] Packages table with version, architecture, vendor
- [ ] Open ports table with protocol, PID, process
- [ ] Running processes table with CPU/memory
- [ ] Browser extensions table
- [ ] System services table with state/startup type
- [ ] Local users and groups tables

## Phase 16: Alerts Timeline Rebuild
- [ ] Dense SOC-grade alert table with rule ID, description, agent, level, timestamp
- [ ] Severity heatmap (hour × day-of-week)
- [ ] Rule level distribution bar chart
- [ ] Top firing rules table
- [ ] Alert detail panel with raw JSON
- [ ] Time range selector with presets

## Phase 17: Vulnerabilities Rebuild
- [x] Global Vulnerability Score (weighted CVSS)
- [x] Severity distribution donut
- [x] Most exploited packages table
- [x] CVE detail table with NVD deep-links
- [x] Status breakdown (active/fixed/pending)
- [x] Affected agents count per CVE

## Phase 18: MITRE ATT&CK Rebuild
- [x] Full tactic × technique matrix (ATT&CK navigator style)
- [x] Technique drill-down with alert counts
- [x] Tactic distribution over time (time series)
- [x] Threat group cards
- [x] Technique detail panel with description and references

## Phase 19: Compliance Scorecards Rebuild
- [x] Framework selector tabs (PCI DSS, NIST 800-53, HIPAA, GDPR, TSC)
- [x] Compliance score gauge per framework
- [x] SCA pass/fail/not-applicable pie charts
- [x] Failed checks table with remediation guidance
- [x] Executive summary exportable view

## Phase 20: FIM Rebuild
- [x] File change timeline chart
- [x] Modified files table with before/after hash comparison
- [x] File permission changes tracking
- [x] Agent-level scan status cards
- [x] Syscheck event detail with raw JSON

## Phase 21: Cluster Health (New Page)
- [x] Daemon status cards (analysisd, remoted, wazuh-db)
- [x] Event queue usage gauge
- [x] Daemon uptime tracking table
- [x] Cluster topology visualization (master + workers)
- [x] Configuration validation status
- [x] Manager stats hourly ingestion chart

## Phase 22: Navigation, Tests, QA
- [x] Update sidebar with new pages (IT Hygiene, Cluster Health)
- [x] Write vitest tests for new backend endpoints (29 passing)
- [x] Final TypeScript compilation check (0 errors)
- [x] Save checkpoint

## Phase 23: FULL Dashboard Population Rebuild (SecondSight Quality)
- [x] SOC Console: Dense KPI row (Total Agents, Active, Alerts 24h, Critical Events, EPS), populated area chart, top talkers pie, MITRE tactic bars, recent alerts table, API connectivity panel, action shortcuts grid
- [x] Fleet Command: Populated agent table with rows, OS distribution donut, version bar chart, status KPIs, agent detail drawer with syscollector data
- [x] Alerts Timeline: Populated alert table with severity/rule/agent columns, hourly bar chart, weekly heatmap grid, rule distribution, severity filter pills
- [x] Vulnerabilities: CVE table with entries, severity donut, CVSS score badges, NVD deep-links, affected agent counts, status breakdown
- [x] MITRE ATT&CK: Full 14-column tactic matrix with technique cells, detection coverage %, technique detail panel, tactic distribution chart
- [x] Compliance: Framework scorecards with pass/fail/score, SCA policy table, failed checks with remediation, compliance trend
- [x] FIM: File change table with hashes, event distribution chart, scan status cards, file detail dialog
- [x] IT Hygiene: Package/port/process tables with data, tabbed layout, agent selector
- [x] Cluster Health: Daemon status grid, hourly ingestion chart, cluster topology cards, config validation
- [x] Remove WazuhGuard blocking — show dashboards with API data when connected, graceful empty states when not
- [x] Final QA all pages populated
- [x] Save checkpoint

## Phase 24: Fallback Sample Data (API shape-matched)

- [x] Create shared mock data module (client/src/lib/mockData.ts)
- [x] SOC Console: fallback agents, alerts, rules, manager status, MITRE tactics
- [x] Agent Health: fallback agent list with OS, version, status, groups
- [x] Alerts Timeline: fallback alert entries with timestamps, rule levels, descriptions
- [x] Vulnerabilities: fallback CVE entries with CVSS scores, packages, severity
- [x] MITRE ATT&CK: fallback tactics, techniques, groups, rule mappings
- [x] Compliance: fallback SCA policies with scores, checks with pass/fail
- [x] FIM: fallback syscheck files with hashes, events, permissions
- [x] IT Hygiene: fallback packages, ports, processes, network interfaces
- [x] Cluster Health: fallback daemon statuses, manager info, hourly stats, cluster nodes
- [x] Each page uses mock as fallback, real API data when connected

## Phase 25: Threat Hunting Dashboard (New Page)

- [x] Backend: Uses existing wazuh endpoints for cross-source correlation
- [x] Query Builder: IOC type selector with search input and quick hunt presets
- [x] IOC Search: Search by IP, hash, CVE, filename, rule ID, MITRE ID, username across all data
- [x] Correlation Engine: Cross-reference agents, rules, vulns, FIM, logs, MITRE techniques
- [x] Hunt Timeline: Timestamped entries with severity indicators and source badges
- [x] Hunt history: In-session hunt log with timestamps and match counts
- [x] Results: Expandable source cards with match counts and raw JSON viewer
- [x] IOC Stats: Source distribution pie, severity distribution, data source coverage bars
- [x] Fallback data: Uses mock data from shared module when Wazuh not connected
- [x] Add route (/hunting) and sidebar navigation entry under Detection group
- [x] All 29 existing vitest tests still passing
- [x] Save checkpoint

## Phase 26: SIEM Events Core Page

- [x] Backend: Uses existing wazuh endpoints (manager logs, rules, agents) for unified event view
- [x] Backend: Log sources computed from mock data and live event metadata
- [x] Backend: Event correlation done client-side from normalized event data
- [x] SIEM Events page: Unified event stream table with timestamp, agent, rule, level, description
- [x] SIEM Events page: Log source filter sidebar with event counts per source
- [x] SIEM Events page: Severity and agent filter controls
- [x] SIEM Events page: Severity level filter pills (Critical, High, Medium, Low, Info)
- [x] SIEM Events page: Full-text search across all event fields
- [x] SIEM Events page: Event detail expansion with raw JSON, MITRE mapping, agent info, data fields
- [x] SIEM Events page: MITRE technique filter for correlation
- [x] SIEM Events page: Log source distribution chart (events by source)
- [x] SIEM Events page: Event volume timeline bar chart (hourly distribution)
- [x] SIEM Events page: Top rules bar chart with hit counts
- [x] SIEM Events page: Agent filter and event counts per agent
- [x] SIEM Events page: KPI row (Total Events, Critical, High, Medium, Low, Log Sources)
- [x] Fallback data: MOCK_SIEM_EVENTS and MOCK_LOG_SOURCES with realistic data
- [x] Sidebar: Added SIEM Events under Detection group
- [x] Route wired in App.tsx at /siem
- [x] All 29 vitest tests still passing
- [x] Save checkpoint

## Phase 27: Ruleset Explorer + Related Events + Saved Searches

### Ruleset Explorer Page
- [x] Rule search with text filter, level filter, group filter
- [x] Rule detail panel with description, groups, PCI/HIPAA/GDPR mappings, MITRE references
- [x] Decoder tab with decoder search, detail view, parent decoder chain
- [x] Rule level distribution chart
- [x] Rule group distribution chart
- [x] Decoder type distribution chart
- [x] Fallback mock data for rules and decoders
- [x] Route /rules and sidebar entry

### Related Events Correlation Panel (SIEM Events)
- [x] "Related Events" expandable section in event detail
- [x] Same-agent events within configurable time window
- [x] Same-rule events across agents
- [x] Same MITRE technique events
- [x] Time window selector (5m, 15m, 1h, 4h, 24h)
- [x] Correlation count badges

### Saved Search Queries
- [x] Database table: saved_searches (id, userId, name, type, filters, createdAt, updatedAt)
- [x] Backend CRUD: create, list, update, delete saved searches
- [x] Save search button in SIEM Events page
- [x] Save search button in Threat Hunting page
- [x] Load saved search dropdown in both pages
- [x] Delete saved search functionality
- [x] Write vitest tests for saved search CRUD (15 tests passing)
- [x] Save checkpoint

## Phase 28: IT Hygiene Ecosystem — Three-Column Rebuild

- [x] Three-column layout: Software & Network | Extensions & Services | Identity & Access
- [x] Agent selector dropdown for per-agent data
- [x] Packages table with name, version, architecture, vendor, format, description
- [x] Open ports table with protocol, local/remote IP, port, PID, process, state
- [x] Running processes table with PID, name, state, user, PPID, priority, threads, CMD
- [x] Browser extensions table with name, browser, version, description, path
- [x] System services table with name, display name, state, startup type, PID, description
- [x] Local users table with username, UID, GID, home, shell, type badge, last login
- [x] Local groups table with name, GID, members, member count
- [x] KPI summary row with 8 stat cards (packages, ports, processes, extensions, services, running, users, interactive)
- [x] Privilege summary panels for users and privileged groups
- [x] Browser distribution and startup type distribution summaries
- [x] Mock data fallback for all categories (browser extensions, services, users, groups)
- [x] Backend endpoints: agentBrowserExtensions, agentServices, agentUsers, agentGroups2
- [x] Write vitest tests (4 new tests, 48 total passing)
- [x] Save checkpoint

## Phase 29: Multi-Agent Comparison View (Configuration Drift)

- [x] Multi-agent selector (pick 2-5 agents to compare) with checkbox grid
- [x] Comparison mode toggle in IT Hygiene page header ("Compare Agents" / "Exit Comparison")
- [x] Package drift detection: highlight packages present on some agents but not others
- [x] Package version drift: highlight version mismatches across agents
- [x] Service drift detection: highlight services running on some agents but not others
- [x] Service state drift: highlight state mismatches (running vs stopped)
- [x] User/group drift: highlight users/groups present on some agents but not others
- [x] Drift summary KPI cards (total drifts, package drifts, service drifts, user drifts)
- [x] Color-coded drift indicators (present=green, absent=red, version/state mismatch=yellow)
- [x] "Show drift only" filter checkbox
- [x] Drift legend at bottom of comparison table
- [x] Per-agent mock data variants for packages, services, and users (4 agents)
- [x] Lazy-loaded DriftComparison component for performance
- [x] All 48 tests passing, TypeScript clean
- [x] Save checkpoint

## Phase 30: Known-Good Configuration Baselines

- [x] Database table: config_baselines (id, userId, name, description, agentIds JSON, snapshotData JSON, createdAt, updatedAt)
- [x] Backend CRUD: create, list, get, delete baselines (tRPC procedures in server/baselines/baselinesRouter.ts)
- [x] "Save as Baseline" button with dialog (name, description, agent list preview)
- [x] "Load Baseline" dialog with saved baselines list, active indicator, delete
- [x] Live Comparison / Baseline Drift view mode toggle
- [x] Baseline drift engine: computes new, removed, and changed items per agent per category
- [x] Baseline drift table with change type badges (New/Removed/Changed), category filter, agent info
- [x] Baseline metadata display (name, description, date saved, agent badges)
- [x] Baseline drift KPI cards (total changes, package/service/user changes with breakdown)
- [x] Color-coded row backgrounds for drift types (green=new, red=removed, amber=changed)
- [x] Delete baseline from detail view and from load dialog
- [x] Write vitest tests for baseline CRUD (14 tests, 62 total passing)
- [x] Save checkpoint
