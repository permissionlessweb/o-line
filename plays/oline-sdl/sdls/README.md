# O-Line SDL Templates

## Deployment Phases

| Phase | SDL | Services | CPU | Memory | Storage | Tested | Est. Cost (AKT/month) |
|-------|-----|----------|-----|--------|---------|--------|----------------------|
| A  | `a.kickoff-special-teams.yml` | snapshot-node (4 CPU, 16Gi, 250Gi) + seed-node (2 CPU, 8Gi, 50Gi) | 6 | 24Gi | 300Gi | Yes | ~50 AKT |
| B  | `b.left-and-right-tackle.yml` | left-tackle (4 CPU, 16Gi, 60Gi) + right-tackle (4 CPU, 16Gi, 60Gi) | 8 | 32Gi | 120Gi | | |
| C  | `c.left-and-right-forwards.yml` | left-forward (4 CPU, 16Gi, 60Gi) + right-forward (4 CPU, 16Gi, 60Gi) | 8 | 32Gi | 120Gi | | |
| **Total** | | **8 services across 4 deployments** | **28** | **112Gi** | **840Gi** | | |

> Costs vary by provider. Estimate based on Phase A observed pricing. Fill in as each phase is tested.
