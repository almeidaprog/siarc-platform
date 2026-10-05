"""Optional end-to-end Locust workload through the active n8n May workflow."""
import os, random
from datetime import datetime, timezone
from locust import HttpUser, task, between

RUN_ID=os.environ.get('SIARC_RUN_ID','manual-n8n')
class SIARCN8NUser(HttpUser):
    wait_time=between(0.02,0.08)
    @task
    def event(self):
        payload={'timestamp':datetime.now(timezone.utc).isoformat(),'src_ip':f'10.55.0.{random.randint(1,254)}','dst_ip':'192.168.55.10',
                 'event_type':random.choice(['unknown','port_scan','brute_force','exploit_attempt']),
                 'severity':random.choice(['low','medium','high']),'payload':'synthetic.user@example.org source=10.55.0.12',
                 'extra':{'experiment_run_id':RUN_ID,'test':'n8n-e2e'}}
        self.client.post('/webhook/siarc/evento-governanca',json=payload,name='/webhook/siarc/evento-governanca')
