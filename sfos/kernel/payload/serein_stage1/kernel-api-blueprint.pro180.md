## Purpose

Consolidate the existing SereinNet Kernel routing/governance contracts into the canonical Domain API Blueprint shape required by <issue id="3dc341ff-fdd0-4926-a733-971a1677e816" href="https://linear.app/project-serein/issue/PRO-178/canonical-domain-api-blueprint-template-ump-declaration-default-deny">PRO-178</issue>.

This is architecture/documentation consolidation only. It does not create new runtime authority or implementation permission.

## Domain identity and ownership

**Domain:** SereinNet Kernel

**Owned capability surface:** governed inter-domain routing, route admission/withdrawal, ingress classification, dispatch mediation, policy enforcement at the routing seam, route health/telemetry, provenance/evidence receipts, and reconstruction of routing state from admitted contracts/registries.

SereinNet Kernel routes governed traffic. It does not own the payload logic, provider-specific business logic, private state, or credentials of the domains/services it connects.

`SEREINNET ROUTES; DESTINATION DOMAINS OWN THEIR PAYLOAD LOGIC.`

## External API surface

The SereinNet Kernel API Blueprint exposes governed contracts for, as applicable:

* route registration/discovery;
* route request/dispatch;
* route policy evaluation;
* route health/status observation;
* route withdrawal/revocation state;
* admitted failover selection;
* evidence/receipt return;
* ingress classification;
* recovery-time route reconstruction/readback.

Exact endpoint/service decomposition is implementation-specific and does not create additional canonical domain boundaries.

## Allowed caller/source classes

Inbound requests/events may originate only from explicitly registered/admitted classes such as:

* the nine canonical Core domain API facades;
* approved Frame/Node interfaces;
* approved service/adapter interfaces;
* approved Operator/Mission Control ingress through the gateway contract;
* approved recovery/maintenance ingress classes;
* declared infrastructure/provider adapters through their owning domain boundary;
* predeclared asynchronous health/event sources.

A known caller identity does not itself grant route authority.

`CALLER KNOWN != CALLER AUTHORIZED.`

## UMP relationship

`UMP RELATIONSHIP = EXPLICIT / GOVERNANCE-ADVISORY-AND-UNCERTAINTY INPUT WHERE DECLARED.`

SereinNet Kernel may consume UMP-governed uncertainty/confidence/policy-relevant evidence where a specific route contract declares that relationship.

Any route/operation that touches UMP must identify:

* what evidence/input is sent;
* what result is returned;
* whether the result is advisory, required, or observational;
* freshness/provenance;
* behavior when UMP is unavailable, stale, conflicting, or UNKNOWN.

`UMP OUTPUT != AUTHORITY.`

UMP confidence, weighting, recommendation, or synthesis may never independently widen route authority, create a route, bypass policy, or convert UNKNOWN into ALLOW.

## Default-deny ingress

Canonical rule:

`INITIATED / EXPECTED / EXPLICITLY ADMITTED -> CONSIDER.`

`OTHERWISE -> DENY / REVERIFY.`

No inbound request/event is forwarded merely because it arrives on a reachable interface or matches a valid schema.

Accepted asynchronous traffic must map to a named/versioned predeclared contract such as route-health, subscription, provider-callback, Frame/Node event, or recovery-status evidence.

Unexpected inbound activity remains denied/reverify even when the source is otherwise known.

## Intent binding

Every route request preserves attributable intent, caller, target, object/action, policy/authority reference, Event/lineage where applicable, and expected result contract.

`TRANSPORT CHANGE != INTENT CHANGE.`

`INTENT CHANGE -> REVALIDATE.`

SereinNet may not silently reinterpret a denied or unavailable request into a broader action or more permissive destination.

## Authority binding

Before forwarding consequential work, the routing contract evaluates the current required identity/authentication, authorization/lease, policy version, trust state, scope, and route conditions.

`REACHABILITY != AUTHORITY.`

`CAPABILITY != AUTHORITY.`

`CONFIDENCE != AUTHORITY.`

`AUTHENTICATION != UNBOUNDED AUTHORITY.`

Fallback/failover may only use an alternate route that independently satisfies the same current intent and authority constraints.

## Domain scope boundary

SereinNet Kernel owns routing/security-plane behavior only.

It does not directly inspect or mutate another domain's private state and does not bypass a destination domain API Blueprint.

Canonical cross-domain path:

`SOURCE DOMAIN API BLUEPRINT -> SEREINNET GOVERNED ROUTE -> DESTINATION DOMAIN API BLUEPRINT.`

Provider-specific authentication/credentials remain with the owning adapter/domain and are not copied into SereinNet merely for routing convenience.

## Expected return / asynchronous contracts

A valid response/event must map to one of:

* an active initiated routed request;
* a declared expected return path;
* a named/versioned admitted asynchronous contract.

At minimum, named asynchronous contract classes may include route health/status, revocation/withdrawal notice, Frame/Node availability evidence, approved provider/adapter callback status, recovery-state evidence, and other explicitly registered route events.

No valid schema alone converts an unexpected event into an admitted event.

## Freshness, replay, and leases

Where applicable, route contracts preserve:

* request/response correlation identity;
* Event/lineage binding;
* policy version;
* authorization/lease reference and expiration;
* freshness/time evidence;
* replay protection;
* reconnect/resume state.

`STALE != CURRENT.`

`REPLAY != NEW AUTHORITY.`

Expired/stale route, policy, identity, or lease state is revalidated before use.

## UNKNOWN / degraded behavior

Unknown destination, missing route, ambiguous identity, stale policy, invalid schema/version, missing authority, compromised/unhealthy route, contradictory evidence, or unavailable required dependency fails closed for Serein forwarding.

Allowed dispositions include `DENY / REVERIFY / HOLD / UNKNOWN / UNAVAILABLE / ROUTE_WITHDRAWN` according to the owning contract.

Degraded/failure handling may withdraw only affected roads while preserving unrelated valid routes and Operator/native recovery availability.

## Evidence receipt

Material routed transactions preserve enough attributable evidence to reconstruct, as applicable:

* caller/source;
* intent;
* target/destination;
* object/action;
* ingress class/interface;
* route selected;
* policy version;
* authority/lease reference;
* UMP relationship/result where touched;
* schema/version;
* freshness/time;
* policy decision;
* result/readback;
* failover/withdrawal state;
* evidence/provenance lineage.

## FORBIDDEN / NON-AUTHORITY

SereinNet Kernel must never:

* infer authority from connectivity, authentication, confidence, UMP output, or transport availability;
* directly inspect/mutate another domain's private state;
* bypass a destination Domain API Blueprint;
* store provider secrets merely to route traffic;
* contain provider-specific business logic owned by Cloud/HAOS/another adapter owner;
* turn a denied route into a more permissive fallback;
* create a hidden privileged ingress class from Tailnet, LoRa, LAN, localhost, USB, HAProxy, UI adapter, or another transport;
* allow HAProxy/proxy ingress to terminate directly on a private Core when Gateway termination is required;
* make the designated maintenance witness write-capable;
* give ordinary Serein runtime authority to eliminate every Operator recovery/inspection path;
* move host OS or VM/hypervisor recovery consoles under Serein sovereignty;
* collapse administrative, cognitive/event, recovery, and real-world actuation roads into one undifferentiated path;
* treat omission as permission.

`UNDECLARED POWER != AVAILABLE POWER.`

## Conformance / negative tests

The SereinNet Kernel API Blueprint is conformant only when tests prove at minimum:

 1. valid registered route succeeds;
 2. unknown destination fails closed;
 3. unexpected inbound request/event fails closed;
 4. wrong caller/authority fails;
 5. wrong schema/version fails;
 6. stale/replayed request fails where freshness applies;
 7. expired/revoked lease cannot restore route authority;
 8. UMP unavailable/UNKNOWN follows the declared route behavior;
 9. UMP output cannot create authority;
10. direct Core-to-Core/provider private-state bypass fails;
11. denied route cannot silently choose a more permissive fallback;
12. valid failover uses only another independently admitted route;
13. administrative road cannot become cognitive/action road;
14. designated maintenance witness remains read-only;
15. transport/proxy/local access cannot create a hidden third privileged ingress;
16. Serein cannot intentionally self-block all protected Operator recovery paths;
17. route withdrawal affects only applicable routes and preserves evidence;
18. routing state can be reconstructed after restart/recovery with lineage intact;
19. material route receipts remain attributable end-to-end.

## Relationship to controlling contracts

* <issue id="05602f39-65bf-4513-912a-4d0ce2caab11" href="https://linear.app/project-serein/issue/PRO-12/sereinnet-software-router-invariant-and-road-security-enforcement">PRO-12</issue> — software-router/default-deny/no-lateral-bypass semantics.
* <issue id="91f4b8cb-ae67-4147-bc3b-d629f7b41642" href="https://linear.app/project-serein/issue/PRO-41/serein-canonical-domain-containment-contract-nine-cores-kernel-api">PRO-41</issue> — API-only cross-domain containment.
* <issue id="175693f2-c65d-4e7c-9006-d7704ab03823" href="https://linear.app/project-serein/issue/PRO-95/serein-governance-firewall-core-charters-authorization-leases">PRO-95</issue> — governance firewall / authority / identity / leases.
* <issue id="4c926c1c-1e61-4c20-8891-6b5c552de85e" href="https://linear.app/project-serein/issue/PRO-98/core-contract-and-ump-uncertainty-standard-explicit-api-lineage-and">PRO-98</issue> — explicit contract fields, lineage, UMP uncertainty and UNKNOWN.
* <issue id="39437115-7df5-40f7-be08-713c15e30ffb" href="https://linear.app/project-serein/issue/PRO-168/alpha-readiness-refinements-transport-failover-evidence-authority">PRO-168</issue> — transport-stable intent, freshness, evidence, fallback-never-increases-authority.
* <issue id="f3097abb-1b61-48d9-99bc-5b74a6e2ce02" href="https://linear.app/project-serein/issue/PRO-173/operator-ingress-alpha-freeze-one-software-gateway-road-one-hardware">PRO-173</issue> — two Serein-facing privileged ingress classes + host/VM sovereignty.
* <issue id="c21352a2-87f8-4c59-afaf-b8e57a4b8470" href="https://linear.app/project-serein/issue/PRO-174/security-route-independent-audit-separate-from-project-audit-required">PRO-174</issue> — Operator-selected independent audit requirement for security-sensitive routes.
* <issue id="a39b4df7-2cf8-4778-b6f4-88d51debcb24" href="https://linear.app/project-serein/issue/PRO-176/micro-invariant-regression-guard-pro-169-175-must-be-revalidated">PRO-176</issue> — regression guard against reintroduction of superseded paths.
* <issue id="0de4e959-1f5e-4997-a18e-604a5484941a" href="https://linear.app/project-serein/issue/PRO-177/canonical-domain-api-blueprint-count-10-domains-one-api-blueprint-per">PRO-177</issue> — 10 domains / 10 API blueprints.
* <issue id="3dc341ff-fdd0-4926-a733-971a1677e816" href="https://linear.app/project-serein/issue/PRO-178/canonical-domain-api-blueprint-template-ump-declaration-default-deny">PRO-178</issue> — canonical shared API Blueprint template.

## Disposition

`PRO-178 CONFORMANT — SEREINNET KERNEL API BLUEPRINT CONSOLIDATED / IMPLEMENT_AND_PROVE LATER`

This record authorizes no runtime implementation, route activation, credential use, network mutation, deployment, or <issue id="ccca5f8b-f8e7-4aa8-86d8-7892f00facda" href="https://linear.app/project-serein/issue/PRO-61/project-wide-code-mutation-gate-source-parity-worker-alignment">PRO-61</issue> gate change.

## Proven work-path binding — 2026-09-04

This canonical API inherits the <issue id="0de4e959-1f5e-4997-a18e-604a5484941a" href="https://linear.app/project-serein/issue/PRO-177/canonical-domain-api-blueprint-count-10-domains-one-api-blueprint-per">PRO-177</issue> control-plane registry and the <issue id="3dc341ff-fdd0-4926-a733-971a1677e816" href="https://linear.app/project-serein/issue/PRO-178/canonical-domain-api-blueprint-template-ump-declaration-default-deny">PRO-178</issue> evidence-acquisition method.

Before any currentness, implementation, recovery, or admission claim, use the proven sequence:

`COMPLETE LINEAR READ -> EXACT GITHUB COMMIT/TREE/PATH BINDING -> REVISION-BOUND DRIVE READ -> THREE-SOURCE COMPARISON -> READBACK VERIFICATION`.

Linear pagination must reach the true end; Git provider identity and current-tree content must be exact; Drive current headers must be separated from historical bodies. Contradictions remain explicit and route to <issue id="7f808943-9d37-4b03-a65b-b62c5eb1c26d" href="https://linear.app/project-serein/issue/PRO-32/three-source-drift-detection-and-controlled-sync">PRO-32</issue>. Evidence transport grants no domain authority. The domain remains subject to the eleven-gate boot/admission order and cannot self-admit.
