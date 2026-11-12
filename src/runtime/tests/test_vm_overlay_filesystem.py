"""Mount policy uses synthetic proc data, independently of the test host FS."""
from pathlib import Path

import pytest

from dnlab_runtime.vm_overlay_files import local_filesystem
from dnlab_runtime.vm_template import TemplateError


@pytest.mark.parametrize('kind',['ext4','ceph','tmpfs','nfs'])
def test_only_initial_local_profile_is_enabled(monkeypatch,kind):
    values={'/proc/self/fdinfo/17':'pos:\t0\nmnt_id:\t123\n',
            '/proc/self/mountinfo':f'123 1 7:0 / /storage rw - {kind} source rw\n'}
    monkeypatch.setattr(Path,'read_text',lambda path:values[str(path)])
    if kind=='ext4':local_filesystem(17)
    else:
        with pytest.raises(TemplateError,match='ext4 overlay profile'):local_filesystem(17)
