"""
Cyberion Defense Labs — Threat Hunt Analysis Script for Hunt 01 and Hunt 02
"""
import os
import json
import numpy as np
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ZEEK_SSL = os.path.join(WORKSPACE_ROOT, 'datasets', 'mordor_apt29', 'zeek', 'ssl.log')
DISCOVERY_EVTX = os.path.join(WORKSPACE_ROOT, 'datasets', 'EVTX-ATTACK-SAMPLES', 'Discovery', 'dicovery_4661_net_group_domain_admins_target.evtx')

def run_hunt_01():
    print("=== HUNT 01: C2 BEACONING & UNTRUSTED TLS SESSIONS ===")
    sessions = []
    with open(ZEEK_SSL, 'r', encoding='utf-8') as f:
        for line in f:
            ev = json.loads(line)
            if ev.get('id_resp_h') == '192.168.0.4' and ev.get('id_resp_p') == 8443:
                sessions.append(ev)
                
    sessions.sort(key=lambda x: float(x['ts']))
    timestamps = [float(s['ts']) for s in sessions]
    deltas = np.diff(timestamps)
    
    mean_d = float(np.mean(deltas)) if len(deltas) > 0 else 0.0
    std_d = float(np.std(deltas)) if len(deltas) > 0 else 0.0
    cov = (std_d / mean_d) if mean_d > 0 else 0.0
    
    first_sess = sessions[0]
    last_sess = sessions[-1]
    
    print(f"Total C2 SSL sessions: {len(sessions)}")
    print(f"First session timestamp: {first_sess['ts']} | Last session: {last_sess['ts']}")
    print(f"Duration: {float(last_sess['ts']) - float(first_sess['ts']):.2f} seconds")
    print(f"Inter-arrival mean delta: {mean_d:.2f}s, std: {std_d:.2f}s, CoV: {cov:.3f}")
    print(f"Subject: {first_sess.get('subject')}")
    print(f"Issuer: {first_sess.get('issuer')}")
    print(f"Validation Status: {first_sess.get('validation_status')}")
    print(f"JA3: {first_sess.get('ja3')} | JA3S: {first_sess.get('ja3s')}")

def run_hunt_02():
    print("\n=== HUNT 02: ACTIVE DIRECTORY DOMAIN RECONNAISSANCE (T1087.002, T1069.002) ===")
    print(f"Analyzing {DISCOVERY_EVTX}...")
    records = []
    with evtx.Evtx(DISCOVERY_EVTX) as log:
        for i, rec in enumerate(log.records()):
            tree = ET.fromstring(rec.xml())
            eid = tree.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
            edata = tree.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            props = {'rec': i, 'eid': eid.text if eid is not None else ''}
            if edata is not None:
                for d in edata.findall('{http://schemas.microsoft.com/win/2004/08/events/event}Data'):
                    if d.get('Name') and d.text:
                        props[d.get('Name')] = d.text
            records.append(props)
            
    print(f"Total records in 4661 discovery log: {len(records)}")
    object_servers = {}
    object_types = {}
    users = {}
    for r in records:
        oserv = r.get('ObjectServer', 'unknown')
        otype = r.get('ObjectType', 'unknown')
        u = r.get('SubjectUserName', 'unknown')
        object_servers[oserv] = object_servers.get(oserv, 0) + 1
        object_types[otype] = object_types.get(otype, 0) + 1
        users[u] = users.get(u, 0) + 1
        
    print(f"Subject Users: {users}")
    print(f"Object Servers: {object_servers}")
    print(f"Object Types: {object_types}")
    print(f"Sample Object Names: {[r.get('ObjectName') for r in records[:5]]}")

if __name__ == '__main__':
    run_hunt_01()
    run_hunt_02()
