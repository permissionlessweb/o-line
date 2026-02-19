# Scrimmage: Test Governance Proposals Locally

The purpose is to curate reproducible tests of governance proposals accurately updating the parameters they are tuned to.

## Workflow

1. Setup Test Network(s) with expected parameters
2. Perform Upgrade Proposal & Voting Workflow
3. Confirm Updates and Parameters are applied successfully

We can curate a testing framework that is modular enought to let us resuse a single orchestration script, that accesses independent test workflow scripts/logic.

## TESTING LIBRARIES

- catalyst - load testing tool: <https://github.com/skip-mev/catalyst>
- ironbird - testnet orchestration: <https://github.com/skip-mev/ironbird>
