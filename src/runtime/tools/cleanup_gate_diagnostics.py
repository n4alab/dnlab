"""Bounded exception evidence for the gate; no IO or authorization decisions."""
from copy import deepcopy

from cleanup_scope_sources import ScopeComparisonError


def exception_chain(error):
    result, seen = [], set()
    while error is not None and id(error) not in seen and len(result) < 8:
        seen.add(id(error))
        row = dict(type=type(error).__name__, module=type(error).__module__, message=str(error)[:4096])
        if isinstance(error, ScopeComparisonError):
            row['scope_comparison'] = deepcopy(error.diagnostic)
        result.append(row)
        error = error.__cause__ or (None if error.__suppress_context__ else error.__context__)
    return result
