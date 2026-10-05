"""Collect reproducibility metadata: hardware, OS, Python, Docker and SIARC containers."""
from __future__ import annotations
import json, os, platform, shutil, subprocess, sys
from pathlib import Path
from datetime import datetime, timezone
try:
    import psutil
except ImportError:
    psutil=None

DOCKER = ['docker'] if shutil.which('docker') else ['wsl.exe', '--', 'docker']


def cmd(args):
    try:
        p=subprocess.run(args,capture_output=True,text=True,timeout=20)
        return {'ok':p.returncode==0,'stdout':p.stdout.strip(),'stderr':p.stderr.strip(),'exit_code':p.returncode}
    except Exception as e:
        return {'ok':False,'stdout':'','stderr':f'{type(e).__name__}: {e}','exit_code':None}


def safe_env_config():
    vals={}
    p=Path('.env')
    if p.exists():
        for line in p.read_text(encoding='utf-8').splitlines():
            if not line or line.lstrip().startswith('#') or '=' not in line:
                continue
            k,v=line.split('=',1)
            if k in {'SIARC_DB_POOL_SIZE','SIARC_DB_MAX_OVERFLOW','SIARC_DB_POOL_TIMEOUT','SIARC_SANITIZER_ENABLED','POSTGRES_DB'}:
                vals[k]=v
    return vals

def main():
    cpu_freq=None; memory=None
    if psutil:
        try:
            f=psutil.cpu_freq(); cpu_freq=None if not f else {'current_mhz':round(f.current,2),'max_mhz':round(f.max,2)}
        except Exception: pass
        try:
            vm=psutil.virtual_memory(); memory={'total_gib':round(vm.total/1024**3,2),'available_gib_at_capture':round(vm.available/1024**3,2)}
        except Exception: pass
    data={
        'captured_at':datetime.now(timezone.utc).isoformat(),
        'os':{'system':platform.system(),'release':platform.release(),'version':platform.version(),'machine':platform.machine()},
        'cpu':{'processor':platform.processor(),'logical_cores':os.cpu_count(),'physical_cores':psutil.cpu_count(logical=False) if psutil else None,'frequency':cpu_freq},
        'memory':memory,
        'python':{'version':sys.version,'executable':sys.executable},
        'docker_version':cmd(DOCKER+['version','--format','{{json .}}']),
        'docker_compose_version':cmd(DOCKER+['compose','version']),
        'docker_compose_ps':cmd(DOCKER+['compose','ps','--format','json']),
        'git_commit':cmd(['git','rev-parse','HEAD']),
        'git_status':cmd(['git','status','--short']),
        'siarc_safe_config':safe_env_config(),
    }
    out=Path('results/jisa/environment'); out.mkdir(parents=True,exist_ok=True)
    (out/'environment.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
    lines=[f"Captured: {data['captured_at']}",f"OS: {platform.platform()}",f"CPU: {data['cpu']}",f"Memory: {memory}",f"Python: {sys.version.splitlines()[0]}",
           f"Docker: {data['docker_version']['stdout'] or data['docker_version']['stderr']}",f"Compose: {data['docker_compose_version']['stdout'] or data['docker_compose_version']['stderr']}",
           'Containers:',data['docker_compose_ps']['stdout'] or data['docker_compose_ps']['stderr']]
    (out/'environment.txt').write_text('\n'.join(lines),encoding='utf-8')
    print('\n'.join(lines))

if __name__=='__main__': main()
