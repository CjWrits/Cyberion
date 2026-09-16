"""
Analysis script to inspect APT29 Day 1 Mordor dataset
Extracts command lines, process lineages, network connections, and security events.
"""
import zipfile
import json
import os

zpath = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'mordor_apt29', 'apt29_evals_day1_manual.zip')

def inspect_events():
    print(f"Opening {zpath}...")
    with zipfile.ZipFile(zpath, 'r') as z:
        fname = [f for f in z.namelist() if f.endswith('.json')][0]
        with z.open(fname) as f:
            attack_cmds = []
            net_conns = []
            reg_mods = []
            for line in f:
                ev = json.loads(line)
                ch = ev.get('Channel')
                eid = ev.get('EventID')
                
                # Sysmon Process Creation
                if ch == 'Microsoft-Windows-Sysmon/Operational' and eid == 1:
                    cmd = ev.get('CommandLine', '')
                    parent = ev.get('ParentCommandLine', '')
                    user = ev.get('User', '')
                    time = ev.get('UtcTime', '')
                    img = ev.get('Image', '')
                    pimg = ev.get('ParentImage', '')
                    
                    # Look for non-background/interactive commands
                    if not any(ign in cmd.lower() for ign in ['searchprotocolhost', 'searchfilterhost', 'conhost.exe']):
                        attack_cmds.append({
                            'time': time,
                            'user': user,
                            'image': img,
                            'parent_image': pimg,
                            'parent': parent,
                            'cmd': cmd
                        })
                
                # Sysmon Network Connection
                elif ch == 'Microsoft-Windows-Sysmon/Operational' and eid == 3:
                    dst_ip = ev.get('DestinationIp', '')
                    dst_port = ev.get('DestinationPort', '')
                    img = ev.get('Image', '')
                    time = ev.get('UtcTime', '')
                    if dst_ip not in ['127.0.0.1', '::1', '10.0.0.4']: # External / anomalous
                        net_conns.append({
                            'time': time,
                            'image': img,
                            'dst_ip': dst_ip,
                            'dst_port': dst_port
                        })

    print(f"Total significant commands extracted: {len(attack_cmds)}")
    for i, c in enumerate(attack_cmds[:40]):
        print(f"[{c['time']}] USER: {c['user']}")
        print(f"   Parent: {c['parent_image']} -> {c['parent'][:100]}")
        print(f"   Image:  {c['image']}")
        print(f"   Cmd:    {c['cmd'][:120]}")
        print("-" * 60)

    print(f"\nUnique external/anomalous network connections (EID 3): {len(net_conns)}")
    seen_net = set()
    for n in net_conns:
        key = (n['image'], n['dst_ip'], n['dst_port'])
        if key not in seen_net:
            seen_net.add(key)
            print(f"[{n['time']}] {n['image']} -> {n['dst_ip']}:{n['dst_port']}")

if __name__ == '__main__':
    inspect_events()
