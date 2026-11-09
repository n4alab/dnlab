"""Fixture-only loss of complete acknowledgments, never a runtime retry policy."""
from copy import deepcopy


class LostProbeAcknowledgment(RuntimeError):
    pass


class ProbeBoundary:
    def __init__(self,invoke):
        self.invoke=invoke;self.pending=['packets','cleanup'];self.calls=[];self.losses=[]

    def __call__(self,client,request,action,**kwargs):
        row={'host':request['host'],'segment':request['segment'],'request_id':request['request_id'],
             'action':action,'expected_birth':deepcopy(kwargs.get('expected_birth')),'returned':False}
        self.calls.append(row)
        value=self.invoke(client,request,action,**kwargs)
        row['returned']=True
        if self.pending and action==self.pending[0]:
            if value.get('resource_proof')!=kwargs.get('expected_birth'):
                raise RuntimeError('fixture loss boundary original birth differs')
            self.pending.pop(0);self.losses.append(deepcopy(row))
            raise LostProbeAcknowledgment('injected lost '+action+' acknowledgment after durable result')
        return value


class ProbeWorkerCrashed(RuntimeError):
    pass


def crash_after_exec_start(source):
    marker="if __name__=='__main__':main()"
    prefix,suffix=source.rsplit(marker,1)
    if suffix.strip():raise RuntimeError('fixture worker main suffix differs')
    injection="""
_fixture_original_call=DockerExecHTTP.call
def _fixture_call(self,method,path,payload=None,**kwargs):
    result=_fixture_original_call(self,method,path,payload,**kwargs)
    if method=='POST' and path.startswith('/exec/') and path.endswith('/start'):
        os.kill(os.getpid(),9)
    return result
DockerExecHTTP.call=_fixture_call
"""
    return prefix+injection+marker+suffix


def caused_by_worker_crash(error):
    seen=set()
    while error is not None and id(error) not in seen:
        if isinstance(error,ProbeWorkerCrashed):return True
        seen.add(id(error));error=error.__cause__ or error.__context__
    return False
