"""
Extracts the chronological attack timeline for APT29 Day 1.
"""
import zipfile
import json
import os

zpath = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'mordor_apt29', 'apt29_evals_day1_manual.zip')

def extract_timeline():
    events = []
    with zipfile.ZipFile(zpath, 'r') as z:
        fname = [f for f in z.namelist() if f.endswith('.json')][0]
        with z.open(fname) as f:
            for line in f:
                ev = json.loads(line)
                ch = ev.get('Channel', '')
                eid = ev.get('EventID', '')
                utc = ev.get('UtcTime', '') or ev.get('TimeCreated', '')
                
                # Sysmon EID 1 Process Create
                if ch == 'Microsoft-Windows-Sysmon/Operational' and eid == 1:
                    cmd = ev.get('CommandLine', '')
                    pcmd = ev.get('ParentCommandLine', '')
                    img = ev.get('Image', '')
                    user = ev.get('User', '')
                    # Filter out benign Windows noise
                    if any(noise in cmd.lower() for noise in ['searchprotocolhost', 'searchfilterhost', 'conhost.exe --headless', 'backgroundtaskhost', 'runtimebroker']):
                        continue
                    events.append({
                        'timestamp': utc,
                        'source': 'Sysmon-EID1',
                        'user': user,
                        'image': img,
                        'details': f"CMD: {cmd} | PARENT: {pcmd}"
                    })
                
                # Sysmon EID 3 Network Connect
                elif ch == 'Microsoft-Windows-Sysmon/Operational' and eid == 3:
                    dst = ev.get('DestinationIp', '')
                    port = ev.get('DestinationPort', '')
                    img = ev.get('Image', '')
                    if dst not in ['127.0.0.1', '::1', '0:0:0:0:0:0:0:1'] and not dst.startswith('10.0.0.'):
                        events.append({
                            'timestamp': utc,
                            'source': 'Sysmon-EID3',
                            'user': ev.get('User', ''),
                            'image': img,
                            'details': f"CONNECT to {dst}:{port}"
                        })

                # PowerShell EID 4104 Script Block
                elif ch == 'Microsoft-Windows-PowerShell/Operational' and eid == 4104:
                    sdata = ev.get('ScriptBlockText', '')
                    if len(sdata.strip()) > 10 and not any(n in sdata for n in ['prompt', 'Get-Location']):
                        events.append({
                            'timestamp': utc,
                            'source': 'PowerShell-EID4104',
                            'user': ev.get('UserId', ''),
                            'image': 'powershell.exe',
                            'details': f"SCRIPTBLOCK: {sdata[:150]}"
                        })

    events.sort(key=lambda x: str(x['timestamp']))
    print(f"Total extracted attack events: {len(events)}")
    with open(os.path.join(os.path.dirname(__file__), 'apt29_timeline_extracted.json'), 'w', encoding='utf-8') as out:
        json.dump(events, out, indent=2)
    
    # Print sample timeline entries
    for e in events[:50]:
        print(f"[{e['timestamp']}] [{e['source']}] {e['user']} - {e['image']}")
        print(f"    {e['details'][:140]}")

if __name__ == '__main__':
    extract_timeline()
