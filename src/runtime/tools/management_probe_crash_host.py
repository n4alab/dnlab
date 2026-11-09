"""Fixture-only SIGKILL of its own worker after the original exec starts."""
import json
from management_service_diagnostics import DiagnosticHost
from management_probe_recovery import crash_after_exec_start,ProbeWorkerCrashed


class ProbeCrashHost(DiagnosticHost):
    crash_pending=False
    crash_verified=False

    def run_input(self,command,payload,**kwargs):
        envelope=json.loads(payload) if payload else {}
        request=envelope.get('request',{})
        if not self.crash_pending or request.get('action')!='packets':return super().run_input(command,payload,**kwargs)
        envelope['source']=crash_after_exec_start(envelope['source']);self.crash_pending=False
        previous=len(self.events)
        try:return super().run_input(command,json.dumps(envelope),**kwargs)
        except Exception as error:
            if len(self.events)>previous and self.events[-1]['exit_code']==-9:
                self.crash_verified=True
                raise ProbeWorkerCrashed('fixture worker SIGKILL after detached exec start verified') from error
            raise
