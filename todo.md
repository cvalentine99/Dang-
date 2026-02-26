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

## Phase 31: Scheduled Baseline Auto-Capture

- [ ] Database table: baseline_schedules (id, userId, name, agentIds, frequency, enabled, lastRunAt, nextRunAt, retentionCount, createdAt)
- [ ] Backend: Schedule CRUD (create, list, toggle, delete, triggerNow)
- [ ] Backend: BaselineScheduler service with interval-based execution
- [ ] Frontend: Schedules tab in DriftComparison with schedule list
- [ ] Frontend: Create schedule dialog (name, frequency, retention, agent selection)
- [ ] Frontend: Toggle schedule on/off, delete, trigger now
- [ ] Frontend: Schedule status badges (active/paused/overdue)
- [ ] Frontend: Baseline history timeline showing auto-captured snapshots
- [ ] Write vitest tests for schedule CRUD
- [ ] Save checkpoint

## Phase 32: Wazuh Indexer API Integration (Critical Gap)

### Backend — Indexer Client & Router
- [x] Create indexerClient.ts (Elasticsearch/OpenSearch HTTP client, Basic Auth, TLS skip, rate limiting)
- [x] Add WAZUH_INDEXER_HOST, WAZUH_INDEXER_PORT, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS env vars
- [x] Create indexerRouter.ts with query builders for all 5 index patterns
- [x] Wire indexer router into routers.ts
- [x] Indexer status check endpoint (isIndexerConfigured + cluster health)

### Indexer Endpoints — wazuh-alerts-*
- [x] alertsSearch: full-text search with time range, agent, rule level, MITRE tactic filters
- [x] alertsAggByLevel: severity distribution aggregation (date_histogram + terms)
- [x] alertsAggByAgent: top agents by alert count (top talkers)
- [x] alertsAggByMitre: MITRE tactic/technique distribution over time
- [x] alertsAggByRule: top triggered rules aggregation
- [x] alertsTimeline: time-series alert count (date_histogram)
- [x] alertsGeoAgg: geographic distribution by GeoLocation.country_name
- [x] alertsComplianceAgg: filter by pci_dss_*, hipaa_*, nist_*, gdpr_* tags

### Indexer Endpoints — wazuh-states-vulnerabilities-*
- [x] vulnSearch: global vulnerability search across all agents
- [x] vulnAggBySeverity: severity distribution aggregation
- [x] vulnAggByAgent: top vulnerable agents
- [x] vulnAggByPackage: most exploited packages
- [x] vulnAggByCVE: top CVEs across fleet

### Indexer Endpoints — wazuh-monitoring-*, wazuh-statistics-*, wazuh-archives-*
- [x] monitoringAgentHistory: agent connection state over time
- [x] statisticsPerformance: manager performance metrics over time
- [x] archivesSearch: raw event search for forensic investigation

### Mock Data for Indexer
- [ ] Create MOCK_INDEXER_ALERTS with realistic alert documents
- [ ] Create MOCK_INDEXER_VULNS with vulnerability state documents
- [ ] Create mock aggregation response shapes

### Frontend — SOC Console Upgrades
- [ ] Indexer connectivity indicator (green when connected)
- [ ] Threat Trends Area Chart (alerts over time from wazuh-alerts-*)
- [ ] Top Talkers Pie Chart (top agents by alert count)
- [ ] Alert severity distribution bar chart
- [ ] Top triggered rules table from Indexer aggregation

### Frontend — Vulnerabilities Page Upgrade
- [ ] Global Vulnerability Score (CVSS weighted average)
- [ ] Fleet-wide CVE aggregation table
- [ ] Most exploited packages chart
- [ ] Top vulnerable agents ranking

### Frontend — SIEM Events Upgrade
- [ ] Indexer-powered alert search (replaces mock events when Indexer connected)
- [ ] Time range picker for Indexer queries
- [ ] Real alert detail with full _source document

### Frontend — Compliance & MITRE Upgrades
- [ ] Framework-specific alert filtering (PCI DSS, HIPAA, NIST, GDPR)
- [ ] Compliance alert trend charts
- [ ] Time-series tactic progression chart from Indexer data

### Tests
- [ ] Write vitest tests for indexer client
- [ ] Write vitest tests for indexer router endpoints
- [ ] Save checkpoint

## Phase 33: OTX Threat Intelligence Feed
- [x] Store OTX API key as server-side secret
- [x] Backend OTX proxy router: subscribed pulses, pulse search, pulse detail, IOC lookup (11 endpoints)
- [x] IOC indicator search (IPv4, IPv6, domain, hostname, file hash, URL, CVE)
- [x] Pulse detail with IOC list, targeted countries, industries, MITRE mappings
- [x] Threat Intel page under Operations in sidebar with Amethyst Nexus theme
- [x] Pulse feed browser with search and pagination
- [x] IOC lookup tool with type-specific result rendering
- [x] Subscribed feed dashboard with recent pulses and stats
- [x] Write vitest tests for OTX router (11 tests, 73 total passing)
- [x] Save checkpoint

## Phase 34: SOC Console Indexer Upgrade & SIEM OTX Cross-Reference

### SOC Console Indexer-Powered Panels
- [x] Threat Trends area chart (stacked by severity from alertsAggByLevel, with mock fallback)
- [x] Top Talkers donut chart (agents ranked by alert volume from alertsAggByAgent, with mock fallback)
- [x] Geographic Heatmap (country-level alert distribution from alertsGeoAgg, with mock fallback)
- [x] Top Firing Rules table (rules ranked by trigger count from alertsAggByRule, with mock fallback)
- [x] MITRE Tactic Activity bar chart (trending tactics from alertsAggByMitre, with mock fallback)
- [x] Indexer connectivity indicator (green/yellow/red from indexer.status)
- [x] Dual-source badges showing data source (Server API / Indexer / Mock) on every panel
- [x] Graceful fallback to mock panels when Indexer not configured
- [x] EPS gauge from Indexer alert count per second
- [x] Time range selector (1h/6h/24h/7d/30d) for Indexer queries

### SIEM Events OTX IOC Cross-Reference
- [x] "Check in OTX" button on Source IP (public IPs only, skips RFC1918)
- [x] "Check in OTX" button on Destination IP (public IPs only, skips RFC1918)
- [x] OTX lookup dialog with pulse count, reputation, country, ASN KPI cards
- [x] Threat verdict badge (Malicious/Suspicious/Clean) based on pulse count
- [x] Related threat pulses list with author, date, tags, and OTX links
- [x] Validation tags display
- [x] All 73 tests passing, TypeScript clean
- [x] Save checkpoint

## Phase 35: SOC### Alerts Timeline Rebuild
- [x] Dense SOC-grade alert table with sortable columns (timestamp, rule, level, agent, description)
- [x] Severity heatmap (hour × day-of-week) from alertsAggByLevel with mock fallback
- [x] Rule distribution sidebar from alertsAggByRule with top 15 rules
- [x] Time range presets (1h, 6h, 24h, 7d, 30d)
- [x] Real-time EPS indicator from Indexer timeline
- [x] Alert detail dialog with raw JSON viewer and MITRE mapping
- [x] Pagination with configurable page size
- [x] Mock data fallback when Indexer not connected
- [x] Dual-source badges (### Vulnerabilities Dashboard Upgrade
- [x] Global Vulnerability Score gauge (fleet-wide risk metric with weighted severity)
- [x] Fleet-wide CVE table from vulnSearch with search and severity filter
- [x] Most exploited packages treemap from vulnAggByPackage
- [x] Top vulnerable agents bar chart from vulnAggByAgent
- [x] Severity distribution donut from vulnAggBySeverity
- [x] Top CVEs across fleet table from vulnAggByCVE with CVSS scores
- [x] Dual-source badges (Indexer / Server API / Mock)
- [x] Per-agent vulnerability detail tab preserved

### Compliance Dashboard Upgrade
- [x] Framework Alerts tab with framework selector (PCI DSS, HIPAA, NIST 800-53, GDPR, TSC)
- [x] Framework-specific alert counts from alertsComplianceAgg
- [x] Compliance requirement breakdown table with alert counts per requirement
- [x] Compliance trend over time area chart
- [x] Framework KPI cards (total alerts, requirements, top requirement)
- [x] Dual-source badges (Indexer / Mock)

### MITRE ATT&CK Detection Coverage Heatmap
- [x] Detection Heatmap tab with tactic cells colored by coverage percentage
- [x] Horizontal bar chart showing coverage % per tactic
- [x] Coverage legend with intensity scale
- [x] Alert Activity tab with tactic progression timeline (stacked area chart)
- [x] Alerts by Tactic ranked bar list with delta percentages
- [x] Top Techniques by Alert Volume table
- [x] Time range selector (24h, 7d, 30d)
- [x] Dual-source badges (Indexer / Server / Mock)
- [x] 4-tab layout: ATT&CK Matrix | Detection Heatmap | Alert Activity | Threat Groups

### General
- [x] All 77 tests passing, TypeScript clean
- [x] Save checkpoint

## Phase 36: CSV/JSON Export & Analyst Notes System

### CSV/JSON Export Utility
- [x] Create shared export utility (client/src/lib/exportUtils.ts) with CSV and JSON download helpers
- [x] Add export buttons to Alerts Timeline (CSV/JSON for alert table data)
- [x] Add export buttons to Vulnerabilities page (CSV/JSON for CVE table, top packages, top agents)
- [x] Add export buttons to IT Hygiene page (CSV/JSON for packages, ports, processes, services, users, groups)
- [x] Add export buttons to SIEM Events page (CSV/JSON for event table data)
- [x] Add export buttons to SOC Console (CSV/JSON for top firing rules, top talkers)
- [x] Styled export dropdown with Amethyst Nexus glass-morphism theme
- [x] Include timestamp and filter context in exported filenames

### Analyst Notes System (Database-Backed)
- [x] Database table: analyst_notes_v2 (id, userId, entityType, entityId, title, content, severity, tags, createdAt, updatedAt)
- [x] Backend CRUD: create, list, get, update, delete analyst notes (tRPC procedures)
- [x] Backend: List notes by entity (agent, alert, CVE, rule) and by user
- [x] Backend: Search notes by content, tags, entity
- [x] Analyst Notes page: Full notes management with create/edit/delete
- [x] Analyst Notes page: Filter by entity type, severity, tags, date range
- [x] Analyst Notes page: Search across all notes
- [x] Inline note creation from Alerts Timeline (annotate specific alerts)
- [x] Inline note creation from Vulnerabilities page (annotate CVEs)
- [x] Inline note creation from Agent Health (annotate agents)
- [x] Note indicator badges on entities that have notes (NoteCountBadge)
- [x] Note detail panel with expandable content and edit dialog
- [x] Notes export (CSV/JSON) from Analyst Notes page
- [x] Entity count KPI cards on Analyst Notes page
- [x] Write vitest tests for export utility functions (17 tests passing)
- [x] Write vitest tests for analyst notes CRUD (7 tests passing)
- [x] Save checkpoint

## Phase 37: Docker Deployment for Linux x86_64

- [x] Create multi-stage Dockerfile (build + production)
- [x] Create docker-compose.yml with app + MySQL services
- [x] Create .dockerignore for efficient builds
- [x] Create env.docker.template with all required environment variables documented
- [x] Create docker-entrypoint.sh with migration support and health checks
- [x] Create deploy.sh convenience script for build + run
- [x] Graceful degradation for self-hosted (Manus OAuth optional, JWT-only works)
- [x] Add /api/health endpoint for Docker health checks
- [x] Create comprehensive DOCKER.md deployment guide
- [x] Multi-agent code review pass (security, performance, Docker, frontend, backend)
- [x] Apply fixes from code review findings
- [x] Run vitest suite (101 tests passing) and verify Docker build (Vite + esbuild compile clean)
- [x] Save checkpoint

## Phase 38: HTTPS Reverse Proxy (Caddy + Nginx)

- [x] Create Caddyfile with automatic HTTPS and reverse proxy to app
- [x] Create nginx.conf with TLS termination and reverse proxy config
- [x] Create docker-compose.caddy.yml override for Caddy profile
- [x] Create docker-compose.nginx.yml override for Nginx profile
- [x] Create proxy/ssl directory structure for Nginx certs
- [x] Update deploy.sh with --proxy caddy|nginx flag and --generate-certs
- [x] Update env.docker.template with domain/email variables
- [x] Update DOCKER.md with comprehensive HTTPS setup instructions
- [x] Save checkpoint

## Phase 39: GitHub Actions CI/CD Pipeline

- [x] CI workflow: lint, typecheck, vitest on PRs and pushes to main
- [x] CD workflow: Docker build, tag, push to GHCR on main merge
- [x] Multi-platform Docker builds (linux/amd64, linux/arm64)
- [x] Docker layer caching for fast builds (GHA cache)
- [x] Semantic versioning with git tags (v*.*.* triggers)
- [x] GHCR image tagging (latest, sha-xxxxx, semver)
- [x] GitHub Dependabot configuration for dependency updates
- [x] Release workflow with auto-generated changelog
- [x] CI/CD documentation in DOCKER.md
- [x] README badges for CI status and container registry
- [x] README.md with project overview, architecture, quick start
- [x] Push workflows to GitHub repository
- [x] Fix CI-incompatible tests (database mocking, env var skipping)
- [x] Fix Docker image name (trailing hyphen → dang-siem)
- [x] CI passing: all 3 jobs (Typecheck, Test, Build) green
- [x] Docker Build passing: multi-platform image pushed to ghcr.io/cvalentine99/dang-siem:latest
- [x] Save checkpoint

## Phase 40: Geographic Threat Distribution Map

- [x] Replace table-based Geographic Threat Distribution with interactive map
- [x] Build ThreatMap component with country-level threat heatmap circles
- [x] Country hover tooltips showing threat count, avg severity, and threat level
- [x] Amethyst Nexus themed map (dark tiles, purple/violet heat colors, severity legend)
- [x] Save checkpoint

## Phase 41: Threat Map Enhancements (GeoIP, Click-to-Filter, Pulse Animation)

- [x] Backend: GeoIP enrichment endpoint (IP-to-country lookup using geoip-lite/MaxMind GeoLite2)
- [x] Backend: Aggregate alert source IPs to country-level threat data with real coordinat- [x] Frontend: Replace static country centroids with GeoIP-resolved attack origin points
- [x] Frontend: Animated pulse effect on highest-severity threat circles (critical/high)
- [x] Frontend: Click-to-filter — clicking a country circle navigates to Alerts Timeline filtered by that country
- [x] Frontend: Alerts Timeline accepts country/srcip filter from URL search params with active filter badges
- [x] Backend: alertsSearch now supports srcip and geoCountry filter params
- [x] Save checkpoint

## Phase 42: Dockerfile Fix — --prod strips Vite runtime dependency

- [x] Fix Dockerfile line 49: copy full node_modules from deps stage instead of reinstalling with --prod
- [x] Save checkpoint

## Phase 43: Fix production runtime error

- [x] Diagnose runtime error: TypeError Invalid URL from getLoginUrl() when VITE_OAUTH_PORTAL_URL not set in Docker
- [x] Fix: Add guard in const.ts getLoginUrl() — returns "/" fallback when OAuth vars missing, try/catch on URL construction
- [x] Save checkpoint

## Phase 44: Local Auth, Env Validation, Status Dashboard

### Local JWT Auth for Docker
- [x] Add passwordHash column to users table (nullable for OAuth users)
- [x] Create local auth service (bcrypt password hashing, JWT token generation/verification)
- [x] Create local auth tRPC endpoints (register, login) that work alongside existing OAuth
- [x] Auto-detect auth mode: if OAUTH_SERVER_URL is set use Manus OAuth, otherwise use local auth
- [x] Seed default admin user via env vars (LOCAL_ADMIN_USER, LOCAL_ADMIN_PASS)
- [x] Build login page UI with Amethyst Nexus styling
- [x] Build register page UI (first user becomes admin, star badge)
- [x] Update DashboardLayout sign-in button to auto-detect auth mode and route to /login or OAuth
- [x] Add /login and /register routes outside DashboardLayout in App.tsx

### Environment Variable Validation
- [x] Add boot-time validation for required env vars (DATABASE_URL, JWT_SECRET)
- [x] Add boot-time validation for Wazuh env vars (WAZUH_HOST, WAZUH_USER, WAZUH_PASS)
- [x] Print clear error messages with missing variable names and descriptions
- [x] Categorize as required vs optional with graceful degradation

### Status Dashboard
- [x] Create /api/status endpoint with Wazuh Manager, Wazuh Indexer, and MySQL connectivity checks
- [x] Build /status frontend page with connection status cards and latency indicators
- [x] Show environment configuration summary (which auth mode, which features enabled)
- [x] Auto-refresh status checks with manual retry button
- [x] Write vitest tests for local auth, env validation, and status endpoint
- [x] Fix /api/status timeout (parallel checks with 5s timeout instead of 45s sequential)
- [x] Save checkpoint

## Phase 45: Docker Compose Self-Hosted Deployment

### Docker Configuration
- [x] Review and update multi-stage Dockerfile (correct build output paths, add package.json for runtime)
- [x] Update .dockerignore to exclude dev files
- [x] Update docker-compose.yml — add LOCAL_ADMIN_USER/PASS, make Wazuh vars optional (not :?required)
- [x] Update env.docker.template with local auth vars and descriptions
- [x] Verify docker-entrypoint.sh handles DB wait, migrations, and server start
- [x] Update DOCKER.md — add local auth section, status dashboard docs, env validation docs
- [x] Update deploy.sh — make Wazuh vars optional with warnings instead of hard errors
- [x] Verify TypeScript compiles clean (0 errors) and all 127 tests pass
- [x] Save checkpoint

## Phase 46: GitHub Push & Docker Build Verification

### GitHub Push
- [x] Push all changes to cvalentine99/Dang- repository (commit baa93c6)

### Docker Build Test
- [x] Run docker compose build to verify the multi-stage Dockerfile builds successfully (fixed missing geoipService.ts)
- [x] Run docker compose up -d to start app + MySQL containers
- [x] Verify MySQL container reaches healthy state (instant)
- [x] Verify app container starts and passes health check (status: healthy)
- [x] Verify environment validation prints correct output on startup (clear diagnostics with ✅/⚠️)
- [x] Verify database migrations run successfully ("migrations applied successfully")
- [x] Test /api/health endpoint returns 200 ({status:"healthy",database:"connected"})
- [x] Test /api/status endpoint returns connectivity info (database connected, wazuh not_configured)
- [x] Test local auth login flow — admin login ✅, wrong password rejected ✅, new user registration ✅
- [x] Fix: missing geoipService.ts in GitHub repo
- [x] Fix: Dockerfile corepack→npm for better network compatibility

## Phase 47: Admin User Management & Status Auto-Refresh

### Admin User Management Panel (/admin/users)
- [x] Add admin-only tRPC procedures: list, updateRole, resetPassword, toggleDisabled
- [x] Add isDisabled column to users table (migration 0008)
- [x] Build /admin/users page with user table, role badges, status badges, search, pagination
- [x] Implement role promote/demote (admin ↔ user) with confirmation dialog
- [x] Implement password reset (admin sets new password) with dialog — local auth only
- [x] Implement disable/enable user toggle with confirmation dialog
- [x] Add /admin/users route and Admin sidebar group with User Management entry
- [x] Prevent admin from demoting/disabling themselves (self-protection)
- [x] Block disabled users from logging in (localAuthService check)
- [x] Write 16 vitest tests (access control, self-protection, input validation, list query)

### Status Dashboard Auto-Refresh
- [x] Add operator-controlled auto-refresh interval selector (Off, 15s, 30s, 60s, 5m)
- [x] Show countdown timer when auto-refresh is active
- [x] Auto-refresh cleans up on unmount and interval change
- [x] Styled with Amethyst Nexus glass-morphism theme
- [x] All 143 tests passing, TypeScript clean

## Phase 48: HybridRAG Knowledge Graph Integration

### Knowledge Graph Database Schema
- [x] Create graph_endpoints table (agent_id, hostname, ip_address, os_version, architecture)
- [x] Create graph_processes table (process_name, pid, state, startup_type, endpoint FK)
- [x] Create graph_network_ports table (port_number, protocol, state, process FK)
- [x] Create graph_software_packages table (package_name, version, architecture, vendor, endpoint FK)
- [x] Create graph_identities table (username, uid, shell, is_admin, endpoint FK)
- [x] Create graph_vulnerabilities table (cve_id, cvss_score, severity, software_package FK)
- [x] Create graph_security_events table (rule_id, mitre_tactic, timestamp, severity_level, endpoint FK)
- [x] Create graph_sync_status table (last_sync, entity_counts, status)
- [x] Create investigation_sessions + investigation_notes tables
- [x] Run migrations (0009_fresh_marrow.sql)

### ETL Pipeline (Wazuh Indexer → Graph Tables)
- [x] Build ETL service (etlService.ts) with 7 sync functions
- [x] Sync wazuh-states-vulnerabilities-* → graph_vulnerabilities
- [x] Sync wazuh-alerts-* → graph_security_events (incremental)
- [x] Sync Wazuh Server API syscollector → endpoints, processes, network_ports, identities
- [x] Add incremental sync support (track last sync timestamp via graph_sync_status)
- [x] Create tRPC procedures for manual sync trigger and status (graphRouter.ts)

### Agentic LLM Pipeline
- [x] Build intent analysis module (structured JSON output with NER)
- [x] Build graph query module (graphQueryService.ts with SQL JOINs)
- [x] Build indexer search module (multi_match + BM25 queries)
- [x] Build context assembly module (parallel retrieval via Promise.all)
- [x] Build LLM synthesis module (SecondSight persona, chain-of-thought)
- [x] Build follow-up suggestion generator
- [x] Create tRPC mutation for analyst chat (graphRouter.ts)

### Security Analyst Chat UI (/analyst)
- [x] Build chat interface with message history and SecondSight persona
- [x] Show LLM responses with markdown rendering (Streamdown)
- [x] Display retrieval sources (Knowledge Graph, Wazuh Indexer, LLM Synthesis badges)
- [x] Add raw JSON evidence toggle per message
- [x] Show retrieval source indicators
- [x] Add 6 suggested query buttons for common security questions

### Knowledge Graph Visualization (/graph)
- [x] Build interactive force-directed graph with D3.js
- [x] Display entity nodes with type-specific colors (7 entity types)
- [x] Display relationship edges between entities
- [x] Click-to-inspect node details panel
- [x] Entity type filter toggles (bottom bar)
- [x] Search entities with text input
- [x] Zoom/pan/reset controls
- [x] Graph stats sidebar panel
- [x] Empty state with link to Data Pipeline

### Investigation Workspace (/investigations)
- [x] Investigation sessions (create, list, view detail)
- [x] Analyst notes per investigation (create, delete with timestamps)
- [x] Status management (active, closed, archived) with filter tabs
- [x] Tags for categorization
- [x] Evidence collection placeholder
- [x] Search investigations

### ETL Pipeline Management UI (/pipeline)
- [x] Show sync status per entity type (7 cards with last run, count, status)
- [x] Manual "Run Full Sync" trigger button
- [x] Pipeline flow visualization (Wazuh Server API → Indexer → Knowledge Graph → LLM)
- [x] Entity count summary cards (Total Entities, Entity Types, Last Sync)
- [x] Sync results display with success/failure per entity

### Integration & Testing
- [x] Add routes to App.tsx for /analyst, /graph, /investigations, /pipeline
- [x] Add Intelligence group to sidebar (Security Analyst, Knowledge Graph, Investigations, Data Pipeline)
- [x] Write 20 vitest tests for graph router (stats, ETL, graph queries, investigations CRUD)
- [x] Verify TypeScript compiles clean (0 errors)
- [x] Visual verification of all 4 pages in browser
- [x] All 161 tests passing
- [x] Save checkpoint

## Phase 49: GitHub Push + Docker Rebuild + Report Export + Attack Paths

### GitHub Push & Docker Rebuild
- [x] Sync all latest files to cvalentine99/Dang- (commit f929929, 27 files, 7639 insertions)
- [x] Rebuild Docker image (dang-siem:latest, 1.52GB) — fixed corepack→npm for network compat
- [x] Test full lifecycle: MySQL healthy, migrations ran (17 tables), health check OK, tRPC login OK, admin seeded

### Investigation Report Export
- [x] Backend: reportService.ts generates investigation report data (timeline, notes, metadata)
- [x] Backend: Generate Markdown report string from investigation data
- [x] Backend: Generate styled HTML report with Amethyst Nexus theme
- [x] Frontend: Add "Export MD" and "Export HTML" buttons to investigation detail view
- [x] Frontend: Download triggers browser download of generated files
- [x] Include investigation metadata (title, status, tags, created/updated dates)
- [x] Include all analyst notes with timestamps
- [x] Include evidence summary and timeline entries

### Attack Path Highlighting (Knowledge Graph)
- [x] Backend: attackPathService.ts with multi-hop traversal algorithm
- [x] Backend: Find paths from vulnerability → software_package → endpoint → identity → security_event
- [x] Backend: Score paths by severity (CVSS + alert level composite scoring)
- [x] Frontend: "Attack Paths" toggle button with count badge in Knowledge Graph header
- [x] Frontend: SVG glow filter, animated dashed edges, severity-colored rings on path nodes
- [x] Frontend: Expandable AttackPathPanel with hop-by-hop breakdown and risk scores
- [x] Frontend: Non-path nodes dimmed to 15% opacity when path selected
- [x] Frontend: Kill chain stage labels and severity indicators per hop

### Testing
- [x] Verify TypeScript compiles clean (0 errors)
- [x] All 161 tests passing
- [x] Visual verification: Knowledge Graph with Attack Paths button, Investigations with Export MD/HTML buttons
- [x] Save checkpoint

## Phase 52: Connection Settings Admin Page

### Backend
- [ ] Create connection_settings table (key-value store for runtime config, encrypted values)
- [ ] Build admin tRPC procedures: getConnectionSettings, updateConnectionSettings, testConnection
- [ ] Runtime config layer: Wazuh/Indexer clients check DB settings first, fall back to env vars
- [ ] Test connection endpoint: validate credentials before saving
- [ ] Encrypt sensitive values (passwords) at rest in the database

### Frontend
- [ ] Build /admin/settings page with Amethyst Nexus glass-morphism panels
- [ ] Wazuh Manager section: host, port, username, password fields
- [ ] Wazuh Indexer section: host, port, username, password fields
- [ ] "Test Connection" button per section with live status indicator
- [ ] "Save" button with confirmation dialog
- [ ] Show current source (env var vs database override) per field
- [ ] Add /admin/settings route and sidebar entry under Admin group

### Integration
- [ ] Wire Wazuh client to use runtime config with env fallback
- [ ] Wire Indexer client to use runtime config with env fallback
- [ ] Write vitest tests for connection settings CRUD and access control
- [ ] Verify TypeScript compiles clean

## Phase 53: Fix Data Integration — Real API Only

### SiemEvents — Replace mocked events with real indexer alertsSearch
- [x] Remove all mock/fake event data from SiemEvents page
- [x] Wire up trpc.indexer.alertsSearch for real event data
- [x] Ensure pagination, filtering, severity work with real indexer data
- [x] Keep rules/agents calls (already real)
- [x] Add alertsAggByDecoder endpoint for log source sidebar
- [x] Add alertsTimeline endpoint for hourly event volume chart
- [x] Add decoderName filter to alertsSearch endpoint

### ThreatHunting — Add Indexer queries for historical correlation
- [x] Add indexer alertsSearch queries for IOC-based alert correlation
- [x] Add indexer vulnSearch for cross-agent vulnerability hunting
- [x] Combine Server API metadata with Indexer historical data
- [x] Show Indexer connection status in data source coverage

### ITHygiene/DriftComparison — Real syscollector data
- [x] Add multiAgentSyscollector backend endpoint (batch fetch packages/services/users)
- [x] Replace mock data with real trpc.wazuh.multiAgentSyscollector queries
- [x] Replace mock agent list with real trpc.wazuh.agents query
- [x] Keep mock data as graceful fallback when Wazuh not connected

### Tests
- [x] Write 8 vitest tests for multiAgentSyscollector endpoint
- [x] Write 14 vitest tests for indexer router (alertsSearch, alertsAggByDecoder, alertsTimeline, vulnSearch)
- [x] All 198 tests passing
- [x] TypeScript compiles clean (0 errors)

## Phase 54: Connection Settings Frontend + SSE Alerts + Mock Cleanup

### Connection Settings Admin Page (Frontend)
- [x] Already built in previous phase — /admin/settings page with glass-morphism panels
- [x] Wazuh Manager section: host, port, username, password fields
- [x] Wazuh Indexer section: host, port, username, password fields
- [x] "Test Connection" button per section with live status indicator
- [x] "Save" button with confirmation dialog
- [x] Show current source (env var vs database override) per field
- [x] "Reset to Env Defaults" button per section
- [x] Route /admin/settings and sidebar entry already exist

### Real-Time Alert Streaming (SSE)
- [x] Backend: SSE endpoint at /api/sse/alerts that polls Indexer for new critical alerts
- [x] Backend: Configurable poll interval (default 30s, min 15s), severity threshold filter
- [x] Backend: Connection management (heartbeat every 15s, cleanup on disconnect)
- [x] Backend: Stats endpoint at /api/sse/stats for monitoring
- [x] Frontend: useAlertStream hook consuming SSE with reconnection logic
- [x] Frontend: LiveAlertFeed component on SOC Console with real-time alert display
- [x] Frontend: Alert detail panel with MITRE tactic tags, agent info, decoder
- [x] Frontend: Ability to dismiss/acknowledge/clear streamed alerts
- [x] Frontend: AlertNotificationBell component for sidebar integration
- [x] Frontend: Stream status indicator (connected/connecting/error/indexer N/A)

### Mock Data Cleanup
- [x] Audited all 13 pages importing from mockData.ts
- [x] Found all mock exports are still actively used as graceful fallback across all pages
- [x] Removed only truly unused export (MOCK_RULE_FILES)
- [x] Added documentation header explaining fallback purpose
- [x] Mock data correctly serves as offline/disconnected fallback — cannot be stripped further

### Tests
- [x] Write 10 vitest tests for SSE alertStreamService
- [x] All 208 tests passing
- [x] TypeScript compiles clean (0 errors)

## Phase 55: Bug Fixes

- [x] Fix runtime error on /rules (Ruleset Explorer) page - null-unsafe property access on real API data
- [x] Fix same null-safety issues in SiemEvents.tsx (mitre, pci_dss, gdpr, hipaa, groups, firedtimes, full_log, decoder.parent)
- [x] Make WazuhRule and WazuhDecoder types optional for fields that real API may omit
- [x] Make SiemEvent interface fields optional for real Indexer data
- [x] All 208 tests passing, TypeScript clean (0 errors)

## Phase 56: Wire Remaining Pages to Real Wazuh API

### Audit Results
All 6 pages were already correctly wired to real Wazuh API data via tRPC.
Mock data is used only as graceful fallback when the API is unreachable.
Each page uses the `isConnected ? realData : MOCK_DATA` pattern with SourceBadge indicators.

### AgentHealth
- [x] Already wired: trpc.wazuh.agents, agentSummaryStatus, agentSummaryOs, agentGroups
- [x] Null-safety verified: uses String(item.os ?? ...) and optional chaining throughout

### AlertsTimeline
- [x] Already wired: trpc.indexer.alertsSearch, alertsAggByLevel, alertsAggByRule, alertsAggByAgent
- [x] Null-safety verified: uses (rule as Record<string, unknown>) ?? {} with optional chaining

### MitreAttack
- [x] Already wired: trpc.wazuh.mitreTactics/Techniques/Groups, trpc.indexer.alertsAggByMitre
- [x] Null-safety verified: uses Array.isArray() guards and optional chaining

### Vulnerabilities
- [x] Already wired: trpc.indexer.vulnSearch/vulnAggBySeverity/vulnAggByAgent/vulnAggByPackage/vulnAggByCVE, trpc.wazuh.agentVulnerabilities
- [x] Null-safety verified: uses parseAggs/parseBuckets helpers with null coalescing

### FileIntegrity
- [x] Already wired: trpc.wazuh.syscheckFiles, syscheckLastScan
- [x] Null-safety verified: uses String(f.event ?? f.type ?? "") pattern

### Compliance
- [x] Already wired: trpc.wazuh.scaPolicies/scaChecks, trpc.indexer.alertsComplianceAgg
- [x] Fixed: Framework overview cards now use real Indexer data via new complianceFrameworkCounts endpoint
- [x] Fixed: Added top-level levels aggregation to alertsComplianceAgg endpoint
- [x] Null-safety verified: uses optional chaining and null coalescing throughout

### New Backend Endpoints Added
- [x] indexer.complianceFrameworkCounts: Get alert counts for all 5 compliance frameworks in one query
- [x] indexer.alertsComplianceAgg: Added top-level levels aggregation for severity breakdown

### Tests
- [x] All 208 tests passing
- [x] TypeScript compiles clean (0 errors)

## Phase 57: AlertNotificationBell Integration

- [x] Wire AlertNotificationBell into DashboardLayout sidebar header
- [x] Show persistent unread alert count badge across all pages
- [x] Enhanced bell with full popover dropdown showing recent critical alerts
- [x] Popover includes: status indicator, alert list with severity/MITRE/agent, dismiss/clear actions, SOC Console link
- [x] Supports collapsed sidebar mode (popover opens to the right)
- [x] Auto-acknowledges unread count when popover is opened
- [x] All 208 tests passing, TypeScript clean (0 errors)

## Phase 58: Bug Fix — /rules page crash (persistent)

- [x] Added normalizeRule() and normalizeDecoder() functions to coerce raw API data into safe typed objects
- [x] Added safeStringArray() helper for robust array field handling
- [x] All rule fields now normalized: id (Number), level (Number), description (String), groups/mitre/pci_dss/gdpr/hipaa (safe arrays), details (safe Record)
- [x] All decoder fields now normalized: name (String with decoder_name fallback), position (Number), status/file/path/relative_dirname (String), details (safe Record)
- [x] Removed all ?? [] and ?? "" fallbacks from JSX — no longer needed since normalization guarantees types
- [x] Chart data filtered for Number.isFinite values to prevent NaN in Recharts
- [x] All 208 tests passing, TypeScript clean (0 errors)

## Phase 59: Bug Fix — /rules page crash (real API confirmed working)

- [ ] Fix frontend rendering crash on /rules page — backend APIs confirmed returning data
- [ ] Debug exact field shape mismatch causing the crash with real Wazuh responses
- [ ] Add error boundary to catch and display render errors gracefully

- [x] Rename "SecondSight Analyst" to "Walter" on the Security Analyst page

## Phase: Wire Up Real Refresh Buttons & Auto-Refresh Controls

- [x] Pull latest code from GitHub
- [x] Audit all pages for placeholder/broken refresh controls
- [x] SOC Console: Wire refresh button to invalidate all tRPC queries
- [x] Fleet Command: Wire refresh button to re-fetch agent data
- [x] SIEM Events: Wire refresh button to re-fetch events + savedSearches
- [x] Alerts Timeline: Wire refresh button to re-fetch alerts
- [x] Vulnerabilities: Wire refresh button to re-fetch vuln data
- [x] MITRE ATT&CK: Wire refresh button to re-fetch MITRE data
- [x] Threat Hunting: Wire refresh button to re-fetch hunt results + savedSearches
- [x] Compliance: Wire refresh button to re-fetch SCA data
- [x] File Integrity: Wire refresh button to re-fetch FIM data
- [x] IT Hygiene: Wire refresh button to re-fetch syscollector data
- [x] Cluster Health: Wire refresh button to re-fetch cluster data
- [x] Knowledge Graph: Wire refresh button to re-fetch graph data
- [x] ThreatIntel: Wire onRefresh to invalidate OTX queries (newly added)
- [x] DataPipeline: Add refresh button for sync status + graph stats (newly added)
- [x] Investigations: Add refresh button to invalidate list (newly added)
- [x] All pages use RefreshControl with auto-refresh dropdown (Off/30s/1m/5m/15m)
- [x] Fix pre-existing test failures from GitHub sync (connectionSettings, multiAgentSyscollector, graph limit)
- [x] All 198 tests passing, TypeScript clean

## Phase: Rewire App to Local Wazuh Backend (192.168.50.158)

- [ ] Review current Wazuh client configuration and secrets
- [ ] Update WAZUH_HOST secret to 192.168.50.158
- [ ] Update WAZUH_INDEXER_HOST secret to 192.168.50.158
- [ ] Verify Wazuh Manager API auth flow (POST /security/user/authenticate)
- [ ] Verify Wazuh Indexer connection (GET /_cluster/health)
- [ ] Update wazuhClient.ts for direct local connection
- [ ] Update indexerClient.ts for direct local connection
- [ ] Test Manager API connectivity from sandbox
- [ ] Test Indexer API connectivity from sandbox
- [ ] Fix any connection issues (TLS, auth, ports)
- [ ] Run vitest suite and verify all tests pass
- [ ] Save checkpoint

## Phase: Replace ALL Mock Data with Real Wazuh API Calls

### Audit & Planning
- [x] Catalog every mock data import across all pages
- [x] Map each mock usage to the correct Wazuh REST API endpoint

### SOC Console (Home.tsx)
- [x] Replace MOCK_AGENTS with GET /agents?select=id,name,status,os.name,os.version,version,lastKeepAlive,group
- [x] Replace MOCK_ALERTS with Indexer alertsSearch (wazuh-alerts-*)
- [x] Replace MOCK_MANAGER_STATUS with GET /manager/status + GET /manager/info
- [x] Replace MOCK_RULES with GET /rules?limit=10&sort=-level
- [x] Replace MOCK_MITRE_TACTICS with Indexer alertsAggByMitre

### Fleet Command (AgentHealth.tsx)
- [x] Replace MOCK_AGENTS with GET /agents
- [x] Replace MOCK_AGENT_OS_SUMMARY with GET /agents/summary/os
- [x] Replace MOCK_AGENT_GROUPS with GET /agents/groups

### Alerts Timeline (AlertsTimeline.tsx)
- [x] Replace MOCK_ALERTS with Indexer alertsSearch
- [x] Replace MOCK_ALERT_LEVEL_DISTRIBUTION with Indexer alertsAggByLevel
- [x] Replace MOCK_TOP_RULES with Indexer alertsAggByRule

### Vulnerabilities (Vulnerabilities.tsx)
- [x] Replace MOCK_VULNERABILITIES with Indexer vulnSearch
- [x] Replace MOCK_VULN_SEVERITY with Indexer vulnAggBySeverity
- [x] Replace MOCK_VULN_PACKAGES with Indexer vulnAggByPackage

### MITRE ATT&CK (MitreAttack.tsx)
- [x] Replace MOCK_MITRE_TACTICS with GET /mitre/tactics
- [x] Replace MOCK_MITRE_TECHNIQUES with GET /mitre/techniques
- [x] Replace MOCK_MITRE_GROUPS with GET /mitre/groups

### Compliance (Compliance.tsx)
- [x] Replace MOCK_SCA_POLICIES with GET /sca/{agent_id}
- [x] Replace MOCK_SCA_CHECKS with GET /sca/{agent_id}/checks/{policy_id}
- [x] Replace MOCK_COMPLIANCE_FRAMEWORKS with Indexer alertsComplianceAgg

### FIM (FileIntegrity.tsx)
- [x] Replace MOCK_SYSCHECK_FILES with GET /syscheck/{agent_id}
- [x] Replace MOCK_SYSCHECK_LAST_SCAN with GET /syscheck/{agent_id}/last_scan

### IT Hygiene (ITHygiene.tsx)
- [x] Replace MOCK_PACKAGES with GET /syscollector/{agent_id}/packages
- [x] Replace MOCK_PORTS with GET /syscollector/{agent_id}/ports
- [x] Replace MOCK_PROCESSES with GET /syscollector/{agent_id}/processes
- [x] Replace MOCK_EXTENSIONS with GET /syscollector/{agent_id}/packages (browser filter)
- [x] Replace MOCK_SERVICES with GET /syscollector/{agent_id}/processes (service filter)
- [x] Replace MOCK_USERS with GET /syscollector/{agent_id}/users

### Cluster Health (ClusterHealth.tsx)
- [x] Replace MOCK_DAEMON_STATUS with GET /manager/status
- [x] Replace MOCK_MANAGER_INFO with GET /manager/info
- [x] Replace MOCK_CLUSTER_NODES with GET /cluster/nodes
- [x] Replace MOCK_HOURLY_STATS with GET /manager/stats/hourly

### SIEM Events (SiemEvents.tsx)
- [x] Replace MOCK_SIEM_EVENTS with Indexer alertsSearch
- [x] Replace MOCK_LOG_SOURCES with Indexer alertsAggByDecoder

### Threat Hunting (ThreatHunting.tsx)
- [x] Replace MOCK_HUNT_RESULTS with Indexer alertsSearch + vulnSearch cross-correlation

### Ruleset Explorer (RulesetExplorer.tsx)
- [x] Replace MOCK_RULES with GET /rules
- [x] Replace MOCK_DECODERS with GET /decoders

### Threat Intel (ThreatIntel.tsx)
- [x] Verify OTX API calls are real (no mock fallback)

### Cleanup
- [x] Remove mockData.ts entirely (DELETED)
- [x] Remove all mock imports from page files
- [x] Handle empty states gracefully (no data yet vs API error)

### Validation Contract
- [x] Produce validation contract document (VALIDATION_CONTRACT.md)
- [x] Include endpoint, method, params, response shape, and consuming component

### Testing
- [x] Run vitest suite — 210 pass / 1 timeout (OTX network)
- [x] TypeScript compiles clean (0 errors)
- [ ] Save checkpoint

## Phase: Knowledge Graph Rebuild (Nemotron-3 Nano Hybrid RAG Architecture)
- [x] Finish stripping mock data from RulesetExplorer
- [x] Finish stripping mock data from remaining pages (DriftComparison was last)
- [x] Redesign KG schema: API Ontology Graph (178 endpoints, 1110 params, 1102 responses, 2 auth methods, 21 resources)
- [x] Redesign KG schema: Operational Semantics Graph (16 use cases)
- [x] Redesign KG schema: Schema & Field Lineage Graph (5 indices, 60 fields)
- [x] Redesign KG schema: Error & Failure Graph (9 error patterns)
- [x] Build deterministic graph extraction pipeline from Wazuh OpenAPI spec (extract-wazuh-kg.mjs)
- [x] Implement safety metadata: risk classification (113 SAFE, 42 MUTATING, 23 DESTRUCTIVE)
- [x] Implement trust scoring per endpoint (0.0-1.0 rolling score)
- [x] Implement graph query service with trust-weighted retrieval
- [x] Rebuild Knowledge Graph UI to visualize 4-layer model
- [x] Wire graph into Walter with Nano prompt contract
- [x] Add safety rails: graph-level exclusion, prompt-level prohibition, output validator, confidence gate
- [x] Delete mockData.ts entirely (zero imports remaining)
- [x] Produce validation contract document (VALIDATION_CONTRACT.md)

## Phase: Fancy Agent Activity Visualization
- [x] Build live agent activity feed with console-style output (5 agents: Orchestrator, Graph Retriever, Indexer Retriever, Synthesizer, Safety Validator)
- [x] Add typing/typewriter effects for step-by-step progress
- [x] Add animated spinners, progress bars, status indicators
- [x] Show each agent's work steps with glass-panel Amethyst Nexus styling
- [x] Real-time step completion animations
- [x] Trust score badge (green/yellow/red) per response
- [x] Confidence percentage display
- [x] Safety status indicator (clean/filtered/blocked)
- [x] Expandable provenance details panel
