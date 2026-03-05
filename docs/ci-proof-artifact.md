# CI Proof Artifact — Sprint Truth Hygiene

**Generated:** 2026-03-05  
**Environment:** Sandbox (Ubuntu 22.04, Node 22.13.0)  
**Runner:** `pnpm test -- --run --reporter=verbose`

---

## Test Suite Summary

| Metric | Value |
|--------|-------|
| Test Files | 71 (70 passed, 1 failed) |
| Tests | 2,071 (2,070 passed, 1 failed) |
| Duration | 26.03s |

### Known Failure (Pre-existing)

| Test | File | Reason |
|------|------|--------|
| `executeScheduledCapture returns a result object with success boolean` | `server/baselines/baselineSchedules.test.ts` | Timeout — attempts to reach Wazuh at 192.168.50.158 from sandbox (private network, unreachable) |

This failure is **not related** to the current sprint work. It has been present since the baseline scheduler was added and only fails in the sandbox environment where the Wazuh API is unreachable.

---

## Critical Test Groups — Verification Commands

### 1. UI → Router Param Parity CI Guard (NEW)
```bash
pnpm test -- --run server/wazuh/uiParamParity.test.ts
# Expected: 9 tests pass
```

### 2. Security Auth-Negative Tests (P1 Obj4)
```bash
grep -A5 'securityRbacRules.*rejects unauthenticated' server/wazuh/wazuhRouter.test.ts
grep -A5 'securityActions.*rejects unauthenticated' server/wazuh/wazuhRouter.test.ts
grep -A5 'securityResources.*rejects unauthenticated' server/wazuh/wazuhRouter.test.ts
grep -A5 'securityCurrentUserPolicies.*rejects unauthenticated' server/wazuh/wazuhRouter.test.ts
# Expected: 4 describe blocks, each with UNAUTHORIZED assertion
```

### 3. Parameter Propagation (KG → Schema)
```bash
pnpm test -- --run server/wazuh/paramPropagation.test.ts
# Expected: 8 tests pass
```

### 4. Regression Fixture
```bash
pnpm test -- --run server/wazuh/regressionFixture.test.ts
# Expected: 69 tests pass (27 contracts × multiple assertions)
```

### 5. Broker Warnings
```bash
pnpm test -- --run server/wazuh/brokerWarnings.test.ts
# Expected: 11 tests pass
```

### 6. UI Wiring
```bash
pnpm test -- --run server/wazuh/uiWiring.test.ts
# Expected: 57 tests pass
```

---

## TypeScript Compilation

```bash
npx tsc --noEmit
# Expected: Found 0 errors.
```

---

*This artifact is generated alongside the test run. Re-run `pnpm test -- --run --reporter=verbose` to reproduce.*
