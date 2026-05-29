# AWS VPC subnet policies

Standalone OPA/Rego policy bundle for subnet evidence emitted by the `plugin-aws-vpc` collector.

## Input schema

Each policy evaluates one subnet at a time using:

- `input.subnet`
- `input.subnet_context`

Current subnet context includes the parent VPC, route tables in the VPC, the effective route table for the subnet, whether the route-table association is explicit, network ACLs for the subnet, internet gateways for the VPC, flow logs, and related log groups.

## Current coverage

This bundle currently checks subnet-level networking posture such as:

- required subnet tags
- approved subnet state
- minimum available IPv4 capacity percentage
- route-table association or main route-table fallback
- blackhole routes in the effective route table
- public IP assignment on launch
- VPC or subnet flow-log coverage
- public route restrictions when privacy-tag baselines are configured

## Policy data

Default baselines live in `policies/data.json` and can be overridden by agent-supplied policy data. Current settings cover required tags, approved states, minimum free IP capacity, public IP assignment, flow-log expectations, and privacy-tag baselines for route checks.

## Testing

Run local checks with:

```shell
opa check policies
opa test policies
```

Or use the Makefile wrappers:

```shell
make validate
make test
```

## Bundling

Build the distributable bundle with:

```shell
make build
```

This writes `dist/bundle.tar.gz`.
