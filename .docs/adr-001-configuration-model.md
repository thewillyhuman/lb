# ADR-001 — Configuration Model

**Date:** 2024-03  
**Status:** Accepted

---

## Context

The load balancer forwarder and controller need to know which VIPs to announce and which backend pools to serve. A decision is required on how this configuration reaches each LB node.

The natural alternative — a centralized control plane API holding shared runtime state — was considered and rejected (see below).

---

## Decision

Each LB node reads its configuration from a **local file**. The forwarder and controller watch this file via `inotify` and reload atomically when it changes. There is no shared state, no central API, and no coordination between LB nodes at runtime.

How the configuration file is generated and deployed to LB nodes is **explicitly out of scope** for this project.

---

## Rationale

**The paper itself lists files as a first-class option.**  
The Maglev paper (NSDI 2016, Section 2.2) states configuration objects are *"either read from files or received from external systems through RPC."* Google likely moved toward RPC due to the scale of their global deployment. CERN's scale does not require this.

**A control plane API introduces shared state for no benefit.**  
The rest of the design deliberately avoids shared state between LB nodes — it is the core reason consistent hashing works without coordination. A central API would be the one component that reintroduces a shared mutable state dependency, adding operational complexity and a potential single point of failure.

**Config file deployment is a solved problem at CERN.**  
CERN already operates Puppet, Ansible, and similar tooling to distribute configuration files to infrastructure nodes. The LB node is just another managed host. Using established tooling means the LB project does not need to own a deployment pipeline.

**Auditability and simplicity.**  
A file checked into a git repository gives a full audit trail of every configuration change with no additional infrastructure. Rollback is a git revert.

---

## Consequences

- The LB node binary must implement `inotify`-based file watching and atomic config reload (build new consistent hash tables, swap in, never block the fast path).
- The LB node must handle a missing or malformed config file gracefully on startup: log the error, do not announce any VIPs via BGP until a valid config is loaded.
- All LB nodes in a cluster should have identical config files. Ensuring this is the responsibility of the deployment tooling, not the LB software itself.
- Temporary config divergence between nodes is tolerable: consistent hashing guarantees that even nodes with slightly different views of the backend pool will mostly agree on backend selection.

---

## Future Consideration — Foreman Integration

A natural future evolution is to generate LB configuration files directly from **Foreman hostgroup and environment** definitions:

- A **hostgroup** maps directly to a backend pool — it already represents a set of hosts serving the same role.
- An **environment** (e.g., `production`, `staging`) provides the deployment tier separation.
- A Foreman ENC (External Node Classifier) hook or a dedicated Foreman plugin could render and deploy the LB config file whenever hostgroup membership changes.

This would give teams a single place (Foreman) to manage both their hosts and their load balancer membership, with no separate LB registration step. This integration is a separate project and makes no changes to the LB node software itself — only to how its config file is generated.
