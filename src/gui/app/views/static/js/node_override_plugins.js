/**
 * NodeOverridePlugins - registry for per-kind Properties panel extensions.
 *
 * DeviceCatalog decides which override key belongs to a GUI kind; plugins own
 * the device-specific rendering, event wiring, and form-state normalization.
 */
const NodeOverridePlugins = (() => {
  const plugins = new Map();

  function register(plugin) {
    if (!plugin || !plugin.key) {
      console.warn('NodeOverridePlugins: invalid plugin registration', plugin);
      return;
    }
    plugins.set(String(plugin.key), plugin);
  }

  function get(key) {
    return plugins.get(String(key || '')) || null;
  }

  function render({ nodeData, override }) {
    const plugin = get(override && override.key);
    if (!plugin || typeof plugin.render !== 'function') return '';
    return plugin.render({ nodeData, override });
  }

  function read({ panel, nodeData, override }) {
    const plugin = get(override && override.key);
    if (!plugin || typeof plugin.read !== 'function') return { type: 'none' };
    return plugin.read({ panel, nodeData, override });
  }

  function wire({ panel, nodeData, override }) {
    const plugin = get(override && override.key);
    if (!plugin || typeof plugin.wire !== 'function') return;
    plugin.wire({ panel, nodeData, override });
  }

  function interfaces({ nodeData, override, baseInterfaces }) {
    const plugin = get(override && override.key);
    if (!plugin || typeof plugin.interfaces !== 'function') return baseInterfaces;
    return plugin.interfaces({ nodeData, override, baseInterfaces });
  }

  return { register, get, render, read, wire, interfaces };
})();

