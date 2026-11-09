"""Instrument one original DNS exec in the local diagnostic fixture only."""
import json
from pathlib import Path
from management_service_diagnostics import DiagnosticHost


def instrument(source,root):
    marker="if __name__=='__main__':main()"
    prefix,suffix=source.rsplit(marker,1)
    if suffix.strip():raise RuntimeError('fixture worker main suffix differs')
    directory=Path(__file__).resolve().parents[2]/'multinode/dnlab_multinode/services'
    injection="\n_fixture_dns={'__name__':'_fixture_dns','_BaseWorker':jump['Worker'],'JumphostError':jump['JumphostError'],'canonical':jump['canonical'],'digest':jump['digest']}\n"
    injection+='exec('+repr((directory/'dns_host.py').read_text())+',_fixture_dns)\n'
    injection+="_fixture_capture={'__name__':'_fixture_capture'}\nexec("+repr(Path(__file__).with_name('management_dns_path_capture.py').read_text())+",_fixture_capture)\n"
    injection+="_fixture_capture['install'](Execution,jump['Worker'],_fixture_dns['Worker'],"+repr(str(root))+')\n'
    return prefix+injection+marker+suffix


class DNSPathHost(DiagnosticHost):
    diagnostic_used=False
    def run_input(self,command,payload,**kwargs):
        envelope=json.loads(payload) if payload else {};request=envelope.get('request',{})
        if (not self.diagnostic_used and request.get('action')=='packets'
                and request.get('request',{}).get('packet_profile',{}).get('mode')=='dns-client'):
            envelope['source']=instrument(envelope['source'],self.root);self.diagnostic_used=True
            payload=json.dumps(envelope)
        return super().run_input(command,payload,**kwargs)
