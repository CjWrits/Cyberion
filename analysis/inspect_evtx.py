"""
Fast, targeted EVTX inspector with line buffering and record capping.
"""
import glob
import os
import sys
import Evtx.Evtx as evtx
import xml.etree.ElementTree as ET

sys.stdout.reconfigure(line_buffering=True)
evtx_base = os.path.join(os.path.dirname(__file__), '..', 'datasets', 'EVTX-ATTACK-SAMPLES')

def inspect_category(tactic, max_files=6, max_records=50):
    p = os.path.join(evtx_base, tactic)
    files = glob.glob(os.path.join(p, '*.evtx'))
    print(f"\n==================== {tactic} ({len(files)} files) ====================")
    for f in sorted(files)[:max_files]:
        fname = os.path.basename(f)
        try:
            with evtx.Evtx(f) as log:
                eids = {}
                providers = set()
                records = 0
                sample_text = ""
                for rec in log.records():
                    records += 1
                    if records > max_records:
                        break
                    tree = ET.fromstring(rec.xml())
                    eid = tree.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID')
                    prov = tree.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}Provider')
                    if eid is not None and eid.text:
                        eids[eid.text] = eids.get(eid.text, 0) + 1
                    if prov is not None and prov.get('Name'):
                        providers.add(prov.get('Name'))
                    if not sample_text and records == 1:
                        edata = tree.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
                        if edata is not None:
                            sample_text = ", ".join([f"{data.get('Name')}={data.text}" for data in edata.findall('{http://schemas.microsoft.com/win/2004/08/events/event}Data') if data.text][:3])
                print(f"File: {fname} | EIDs: {dict(list(eids.items())[:4])} | Sample: {sample_text[:100]}")
        except Exception as ex:
            print(f"File {fname}: Error {ex}")

if __name__ == '__main__':
    for cat in ['Credential Access', 'Lateral Movement', 'Defense Evasion', 'Persistence', 'Command and Control']:
        inspect_category(cat, max_files=5, max_records=30)
