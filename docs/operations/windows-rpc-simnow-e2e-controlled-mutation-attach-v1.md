# Windows RPC SimNow E2E controlled mutation attach v1

This is the Issue 291 functional SimNow E2E seam only. It is neither a
production approval nor a fence-acceptance / release approval. The legacy
`RpcServiceApp` must be built first; then make the actual CTP connect through
the fixed connect seam, attach, and only then call `rpc_engine.start(...)`.

```python
from scripts.windows_rpc_durable_fence_v1 import (
    attach_windows_rpc_simnow_e2e_v1,
    connect_windows_rpc_simnow_e2e_v1,
)

connect_windows_rpc_simnow_e2e_v1(
    main_engine=main_engine,
    gateway_setting=gateway_setting,
)
attach_windows_rpc_simnow_e2e_v1(
    rpc_engine=rpc_engine,
    event_engine=event_engine,
    main_engine=main_engine,
    explicit_e2e_authorized=True,
    production_authorized=False,
    live_trading_authorized=False,
    countable_forward=False,
    max_order_volume=1,
)
rpc_engine.start("tcp://*:2014", "tcp://*:4102")
```

Every argument above is exact: `True` / `False` flags are identity checked and
`max_order_volume` is exactly integer `1`. The attach fixes `CTP`,
`account:windows`, `simnow`, and
`C:\quant\durable\execution-final-admission-v1.json`; callers cannot supply a
method, scope, gateway, expected account hash, or path override.
Only the fixed connect seam accepts `gateway_setting`; it passes its private
copy to the actual `main_engine.connect(..., "CTP")` call, then writes one
immutable, sealed runtime binding to the live CTP gateway plus its td/md APIs.
Attach has no setting/front/environment input and rejects a missing, split, or
tampered binding. Do not print, log, serialize, or copy the setting or binding
into an evidence artifact.

Before exposing any typed RPC, the attach verifies all of the following:

- the runtime binding captured at the actual CTP connect has `柜台环境` exactly
  `测试`, a non-empty canonical `用户名`, and one exact front pair:
  `180.168.146.187:10201` with `180.168.146.187:10211`,
  `180.168.146.187:10202` with `180.168.146.187:10212`, or
  `180.168.146.187:10130` with `180.168.146.187:10131` (an exact optional
  `tcp://` prefix is accepted).
  Independently allowlisted but mismatched ports fail. No attach caller input
  can replace this binding.
- `main_engine.get_gateway("CTP")` has matching td/md `userid` values and both
  td/md `login_status is True`.
- the live OMS account mapping has exactly one key, exactly
  `CTP.<connect-binding userid>`, and its account facts match that identity. SHA-256 of
  the canonical raw account id must match the module-pinned Issue 291 hash
  `9d8809bc4525db5796ac9ec140130371352b92041169e02a6da1e4c31d609559`.
  This is `sha256(raw_account_id_utf8)`, not a JSON list/account-keys hash.
  There is no caller-supplied expected hash, and the raw account id must not be
  written into this runbook or deployment evidence.

It permanently freezes legacy `send_order` and `cancel_order`. Its complete RPC
surface is only `install_fence_v1`, `register_receipt_v1`,
`send_order_fenced_v1`, `cancel_order_fenced_v1`, `query_intent_v1`,
`get_execution_snapshot_v1`, and `peek_current_facts_v1`, plus those two frozen
legacy names. Typed sends require a current fence and matching receipt, and the
Windows-side handler accepts only `type(volume) is int and volume == 1`; it
rejects booleans, floats, and all other values before native vn.py send
handling. Attach is one-time and mutually
exclusive with validation-only and reconciliation-only attach; a failed attach
removes typed methods and leaves only frozen legacy denials.

## Mandatory temporary deployment trust gate

This is a temporary network trust boundary, not a new authentication system.
The deployment owner must complete both read-only checks below immediately
before calling the attach. Any mismatch is a hard stop: do not call the attach
and do not start the RPC listener.

On Windows, first read the effective active profiles and their GPO/RSOP
readback. Every active network category must have `Enabled=True`,
`DefaultInboundAction=Block`, and must not disable its active interface alias.
This is a read-only hard gate; a missing ActiveStore or GPO/RSOP readback is a
failure:

```powershell
$activeConnections = @(
  Get-NetConnectionProfile -ErrorAction Stop |
    Where-Object { $_.NetworkCategory -notin @('Unidentified', 'Disconnected') }
)
if ($activeConnections.Count -eq 0) { throw 'Issue291 active firewall profile gate found no active network' }
$activeProfileNames = @($activeConnections | ForEach-Object {
  switch ($_.NetworkCategory) {
    'DomainAuthenticated' { 'Domain' }
    'Private' { 'Private' }
    'Public' { 'Public' }
    default { throw "Issue291 unsupported active network category: $($_.NetworkCategory)" }
  }
} | Select-Object -Unique)
$activeStore = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
$gpoRsop = @(Get-NetFirewallProfile -PolicyStore RSOP -ErrorAction Stop)
$profileReadback = foreach ($name in $activeProfileNames) {
  $effective = @($activeStore | Where-Object Name -eq $name)
  $gpo = @($gpoRsop | Where-Object Name -eq $name)
  if ($effective.Count -ne 1 -or $gpo.Count -ne 1) {
    throw "Issue291 firewall profile readback missing for $name"
  }
  $disabled = @($effective[0].DisabledInterfaceAliases | ForEach-Object { [string]$_ } |
    Where-Object { $_ -and $_ -notin @('None', 'NotConfigured') })
  $aliases = @($activeConnections | Where-Object {
    $connectionProfile = switch ($_.NetworkCategory) {
      'DomainAuthenticated' { 'Domain' }
      'Private' { 'Private' }
      'Public' { 'Public' }
    }
    $connectionProfile -eq $name
  } | ForEach-Object InterfaceAlias)
  if ($effective[0].Enabled -ne $true -or $effective[0].DefaultInboundAction -ne 'Block' -or
      $disabled -contains 'All' -or @($aliases | Where-Object { $disabled -contains $_ }).Count -ne 0) {
    throw "Issue291 firewall profile gate failed for $name"
  }
  [pscustomobject]@{
    Profile = $name
    ActiveStore = [pscustomobject]@{
      Enabled = $effective[0].Enabled
      DefaultInboundAction = $effective[0].DefaultInboundAction
      DisabledInterfaceAliases = $disabled
      PolicyStoreSource = $effective[0].PolicyStoreSource
      PolicyStoreSourceType = $effective[0].PolicyStoreSourceType
    }
    GpoRsop = [pscustomobject]@{
      Enabled = $gpo[0].Enabled
      DefaultInboundAction = $gpo[0].DefaultInboundAction
      DisabledInterfaceAliases = @($gpo[0].DisabledInterfaceAliases)
      PolicyStoreSource = $gpo[0].PolicyStoreSource
      PolicyStoreSourceType = $gpo[0].PolicyStoreSourceType
    }
    ActiveInterfaceAliases = $aliases
  }
}
$profileReadback | ConvertTo-Json -Depth 6
```

Then inspect every enabled inbound allow rule that reaches TCP 2014 or 4102
without changing the host:

```powershell
$wantedPorts = 2014, 4102
function Test-LocalPort([object[]]$specs, [int]$wanted) {
  foreach ($spec in $specs) {
    $text = [string]$spec
    if ($text -eq 'Any' -or $text -eq [string]$wanted) { return $true }
    if ($text -match '^(\d+)-(\d+)$' -and $wanted -ge [int]$Matches[1] -and $wanted -le [int]$Matches[2]) { return $true }
  }
  return $false
}
$observed = @(
  Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow |
    ForEach-Object {
      $rule = $_
      $port = $rule | Get-NetFirewallPortFilter
      $addr = $rule | Get-NetFirewallAddressFilter
      if ([string]$port.Protocol -in @('TCP', '6', 'Any', '256')) {
        foreach ($wanted in $wantedPorts) {
          if (Test-LocalPort @($port.LocalPort) $wanted) {
            [pscustomobject]@{
              Name = $rule.Name
              Port = $wanted
              RemoteAddress = @($addr.RemoteAddress)
            }
          }
        }
      }
    }
)
$observed | ConvertTo-Json -Depth 4
foreach ($wanted in $wantedPorts) {
  $matches = @($observed | Where-Object Port -eq $wanted)
  $remote = if ($matches.Count -eq 1) { @($matches[0].RemoteAddress) } else { @() }
  if ($matches.Count -ne 1 -or $remote.Count -ne 1 -or $remote[0] -ne '192.168.100.89') {
    throw "Issue291 firewall gate failed for TCP $wanted"
  }
}
```

For each port there must be exactly one enabled inbound allow rule, and its
single `RemoteAddress` must be exactly `192.168.100.89`. `Any`, `LocalSubnet`,
ranges, extra addresses, duplicate rules, or any second enabled allow rule are
failures.

For the authorized deployment, the deployment operator must first export a
recoverable firewall backup and preserve the pre-change readback:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backup = "C:\quant\rollback\issue291-firewall-$stamp.wfw"
New-Item -ItemType Directory -Force (Split-Path $backup) | Out-Null
netsh advfirewall export $backup
Get-NetFirewallRule -Direction Inbound |
  Export-Clixml "C:\quant\rollback\issue291-firewall-rules-$stamp.xml"
```

Resolve the exact rule names from the read-only inventory, then disable every
confirmed broad/duplicate 2014/4102 allow rule. Create or retain exactly one
enabled rule per port with `RemoteAddress=192.168.100.89`, TCP, inbound, allow;
do not use `Any` or `LocalSubnet`. Rerun the full read-only gate above and test
2014/4102 from M2 before attach. Preserve this rollback command before changing
rules, and use it if readback or connectivity fails:

```powershell
netsh advfirewall import $backup
```

After rollback, rerun the same rule inventory and M2 connectivity readback; do
not proceed to attach until the exact rules and connectivity are both proven.

On M2, render the deployed Compose model and assert the request proxy has no
host-published port and `gateway-proxy` has exactly the three intended members:

```bash
docker compose -f deployments/docker-compose.final.yml config --format json |
python -c 'import json,sys; c=json.load(sys.stdin); s=c["services"]; req=s["gateway-rpc-request-proxy"]; members=sorted(name for name,value in s.items() if "gateway-proxy" in (value.get("networks") or {})); assert not req.get("ports"); assert members == ["execution-orchestrator","gateway-rpc-publish-proxy","gateway-rpc-request-proxy"]; print("issue291 temporary network gate: PASS")'
```

`control-api`, `frontend-edge`/browser-facing services, and every other service
must be absent from `gateway-proxy`. Run `docker network inspect` against the
actual deployed project network as a second read-only check; its live container
membership must resolve to the same three services. A Compose-only pass is not
enough when live membership differs.

## M2-only negative gate

Run this only on M2 after the final-validation graph is up, before the Windows
attach. It proves that the one M2 execution service can resolve the request
proxy while a non-member service cannot; either unexpected success is a hard
stop. It does not authorize an order, attach, listener start, or retry.

```bash
docker compose -f deployments/docker-compose.final.yml exec -T execution-orchestrator \
  python -c 'import socket; socket.getaddrinfo("gateway-rpc-request-proxy", 1); print("issue291 M2 execution proxy resolution: PASS")'
docker compose -f deployments/docker-compose.final.yml exec -T control-api \
  python -c 'import socket;\ntry: socket.getaddrinfo("gateway-rpc-request-proxy", 1)\nexcept socket.gaierror: print("issue291 M2 non-member negative gate: PASS")\nelse: raise SystemExit("Issue291 M2 non-member unexpectedly resolves gateway proxy")'
```
