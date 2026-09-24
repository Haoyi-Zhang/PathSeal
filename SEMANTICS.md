# Finite semantics and certificate contract

## State and execution

A program declares a finite ordered product of integer fields.  Each field has a
finite modulus and a role used only by experimental baselines.  A state assigns
a legal value to every field.  A bounded call stack is represented explicitly
by a pointer and two slots.

A segment is a straight-line sequence of five operations:

- `set(x,e)` evaluates an expression and writes the result modulo the declared
  field size;
- `assume(e)` terminates the segment with `infeasible` when `e` is zero;
- `emit(tag,args)` appends an observable event;
- `push(e)` writes a token to the next stack slot or reports `stack_error`;
- `pop(e)` checks and removes the top token or reports `stack_error`.

Expressions comprise field reads, integer constants, Boolean connectives,
equality and ordering, modular addition, and a conditional.  A path executes a
fixed sequence of segments and stops at the first non-`ok` result.  Its
observable result consists of the status, ordered events, and selected final
fields when execution succeeds.

## Exact projection

For a segment, explicit concrete domain `D`, output interface `O`, and field
projection `K`, define two states to collide when they agree on `K` but their
segment results differ after projection to `O`.  `K` is exact exactly when no
such pair exists.

For every result-distinguishable pair, record the set of state fields on which
the pair differs.  These sets form the collision hypergraph.  A projection is
exact exactly when it intersects every hyperedge.  PathSeal selects the
minimum-cardinality hitting set, breaking ties by field declaration order.
The summary table contains one result for every projected key.  The decision
version of minimum exact-key synthesis is NP-complete for explicit Boolean
state/observation tables: membership follows by checking a candidate projection,
and a Hitting Set instance is represented by one all-zero state with observation
zero plus one characteristic-vector state with observation one per hyperedge.

## Backward interfaces and composition

Concrete reachable domains are computed forward.  Interfaces are selected
backward.  The last segment exposes the query's final fields; every earlier
segment exposes the exact key required by its successor.  Consequently, a
successful local result is precisely the next table's input interface.  An
induction over the segment sequence establishes equality between table
composition and direct concrete path execution for every initial state in the
embedded domain.

## Rejection witnesses

For an inexact candidate projection, PathSeal returns the canonical colliding
pair with minimum Hamming distance and then lexicographically smallest full
states.  It also returns the minimum-cardinality additional field set that
repairs all collisions, again breaking ties by declaration order.  These are
finite, checkable explanations of why the proposed splice boundary is unsafe.

## Trust boundary

A certificate embeds the complete finite program, initial domain, per-stage
reachable domains, selected interfaces, tables, and optional rejected
projections.  The checker:

1. validates the finite language;
2. re-executes every concrete stage in an independently written semantics;
3. reconstructs each collision hypergraph and minimum key;
4. validates every table and negative witness;
5. composes the tables for every initial state; and
6. compares the result with direct whole-path execution.

The checker shares the JSON schema and mathematical specification with the
producer, but imports none of the producer or model implementation.
