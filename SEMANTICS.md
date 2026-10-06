# Finite semantics and certificate contract

## State and execution

A program declares a finite ordered product of integer fields.  Each field has a
finite modulus and a role used only by experimental baselines.  A state assigns
a legal value to every field.  A bounded call stack is represented explicitly
by a pointer and declared slots (two in the retained campaign). For a capacity
of `C` slots, the pointer field has exactly `C+1` values, `0` through `C`.
Both validators reject smaller or larger pointer carriers before execution.

A segment is a straight-line sequence of five operations:

- `set(x,e)` evaluates an expression and writes the result modulo the declared
  field size;
- `assume(e)` terminates the segment with `infeasible` when `e` is zero;
- `emit(tag,args)` appends an observable event;
- `push(e)` reduces the expression modulo the next slot's size, writes that
  token, and increments the pointer; a full stack reports `stack_error`;
- `pop(e)` on a nonempty stack compares the top token with the expression
  reduced modulo that top slot's size. A matching pop decrements the pointer
  and clears the removed slot to zero. Underflow or a mismatch reports
  `stack_error` without changing the pointer or slot.

Expressions comprise field reads, integer constants, Boolean connectives,
equality and ordering, modular addition, and a conditional.  A path executes a
nonempty fixed sequence of segments and stops at the first non-`ok` result. Its
observable result consists of the status, ordered events, and selected final
fields when execution succeeds.
The final-field list follows declaration order, including the empty query;
both program validators require this canonical interface.
Out-of-carrier integer constants are legal expressions: for a size-two slot,
`push(1); pop(3)` succeeds, whereas `push(1); pop(2)` reports a mismatch.
Failed results retain status and ordered events but expose no selected state
fields. `ExecutionResult.observable` represents this missing interface by
`None`; certificate JSON represents it by an empty `out` object.

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
and a bounded, at-least-one Hitting Set instance is represented by one all-zero state with observation
zero plus one characteristic-vector state with observation one per hyperedge.
Its hardness follows from Set Covering by incidence duality: covering elements
become hyperedges, available sets become fields, and the budget is unchanged.

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
Certificate comparisons preserve JSON scalar types: integer state values,
event arguments, indices, and counts cannot be replaced by Boolean or
floating-point values that compare numerically equal in Python. Boolean
rejection verdicts remain Boolean values.

Subset obligations count candidate projections, including repair search.
Execution accounting includes stage, whole-path and rejection replay; it is
semantic accounting rather than an instruction count. Rejection replay does
not enter the subset counter. The timed campaign disables named rejections.
