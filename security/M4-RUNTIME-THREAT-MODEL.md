# M4 Runtime Threat Model

## Assets
Run state, budgets, task identity, cancellation and failure semantics.

## Threats
- illegal state transitions;
- replay of terminal runs;
- turn-budget exhaustion;
- tenant/task identity substitution;
- exception leakage into authorization state.

## Required controls
The state machine is the sole transition authority. Terminal states are immutable. Turn limits are checked before model execution and failures produce explicit terminal failure codes.
