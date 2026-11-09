"""Read-only public topology loading selected by persisted runtime ownership."""
from pathlib import Path
import yaml

from .config import ConfigError, parse_topology
from .state import load_state


class MissingDeployment(ConfigError):
    pass


def load(topology_file, *, hosts_file=None, require_state=False):
    # Desired management fields cannot authorize a backend conversion. Read
    # only identity first to locate the existing deployment owner.
    path = Path(topology_file)
    raw = yaml.safe_load(path.read_text())
    name = raw.get('name') if isinstance(raw, dict) else None
    if not isinstance(name, str) or not name or name in ('.', '..') or Path(name).name != name:
        raise ConfigError('Valid topology lab identity required')
    state = load_state(name, path.parent)
    if state is None and require_state:
        raise MissingDeployment(f"Lab '{name}' is not deployed")
    from .native_public import backend
    native = state is not None and backend(state) == 'custom'
    options = {'hosts_file': hosts_file}
    if native:
        options['native_management'] = True
    topo = parse_topology(topology_file, **options)
    if topo.name != name or state is not None and state.lab_name != name:
        raise ConfigError('Topology identity changed during owner loading')
    if native:
        if state.management_plan:
            from .management_segments import resolve
            topo, observed = resolve(topo, state.management_plan)
            if observed != state.management_plan:
                raise ConfigError('Management changes require the original preparation operation')
        elif 'management_networks' in raw or any(
            key in (cfg or {}) for cfg in raw.get('topology', {}).get('nodes', {}).values()
            for key in ('management_network', 'management_port')
        ):
            raise ConfigError('Native management declarations require their original ledger')
    return topo, state
