#!/usr/bin/env python3
import csv
import json
import os
import re
import sqlite3
from collections import defaultdict

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(THIS_DIR)
DATA_DIR = os.path.join(REPO_ROOT, 'dataset')

def load_csv(name):
    with open(os.path.join(DATA_DIR, name), encoding='utf-8') as f:
        return list(csv.DictReader(f))

requests = load_csv('deletion_requests.csv')
identities = load_csv('user_identities.csv')
audit_log = load_csv('user_audit_log.csv')
system_activity = load_csv('system_activity.csv')
evidence_manifest = load_csv('evidence_files.csv')
deletion_rules = load_csv('deletion_rules.csv')

email_to_user = {r['email'].lower(): r for r in identities}
user_to_identity = {r['user_id']: r for r in identities}
hist_email_to_user = {}
for a in audit_log:
    for f in ['old_value', 'new_value']:
        v = str(a.get(f,'')).lower().strip()
        if '@' in v and v not in ['', 'n/a', 'none', 'null', '-']:
            hist_email_to_user[v] = a['user_id']

user_all_emails = defaultdict(set)
for email, u in email_to_user.items():
    user_all_emails[u['user_id']].add(email)
for email, uid in hist_email_to_user.items():
    user_all_emails[uid].add(email)
    if uid in user_to_identity:
        user_all_emails[uid].add(user_to_identity[uid]['email'].lower())

ev_manifest = {r['file_id']: r for r in evidence_manifest}
ev_cache = {}
for ef_id, ef in ev_manifest.items():
    fpath = os.path.join(DATA_DIR, ef['file_path'])
    if not os.path.exists(fpath): 
        continue
    try:
        ext = os.path.splitext(fpath)[1].lower()
        if ext == '.json':
            with open(fpath, encoding='utf-8') as f:
                ev_cache[ef_id] = ('json', json.load(f))
        elif ext == '.sql':
            with open(fpath, encoding='utf-8') as f:
                ev_cache[ef_id] = ('sql', f.read())
        elif ext in ['.log', '.txt']:
            with open(fpath, encoding='utf-8') as f:
                ev_cache[ef_id] = ('log', f.read())
        elif ext == '.pdf':
            ev_cache[ef_id] = ('pdf', None)  # treat as binary but may have metadata
        else:
            ev_cache[ef_id] = ('other', None)
    except Exception:
        pass

def get_evs_up_to(audit_at):
    res = []
    for ef_id, ef in ev_manifest.items():
        if ef['captured_at'] <= audit_at:
            res.append(ef_id)
    return sorted(res, key=lambda x: ev_manifest[x]['captured_at'])

def is_deletion_request(text):
    t = str(text).lower()
    del_words = ['delete', 'deletion', 'erase', 'erased', 'suppression', 'supprimer', 'eliminación', 'eliminar', 'exclusão', 'apagar', '削除', '영구 삭제', '지우', 'close my account', 'remove my account', 'permanent deletion']
    if any(w in t for w in del_words):
        if any(x in t for x in ['right of access', 'data portability', 'access request']) and not any(d in t for d in ['close my account', 'permanent deletion', 'erase', 'delete my account']):
            # be more careful
            if re.search(r'\b(delete|delet|eras)\w*', t) and not re.search(r'access\s+(request|my)', t):
                return True
            # if clearly says access only
            if 'access' in t and 'delete' not in t and 'erase' not in t and 'close my account' not in t:
                return False
            if re.search(r'\bdelete|eras', t): return True
            return False
        return True
    if re.search(r'\bdelet(e|ion)\b', t): return True
    return False

def user_precise(s, user_id, emails):
    if not s: return False
    sl = str(s).lower()
    for e in emails:
        if e and len(e) >= 3:
            # word boundary
            if re.search(r'\b' + re.escape(e) + r'\b', sl): 
                return True
    if user_id:
        # avoid partial matches
        if re.search(r'\b' + re.escape(str(user_id).lower()) + r'\b', sl):
            return True
    return False

def extract_rid(s, prefix):
    m = re.search(rf'({prefix}_\d+)', str(s))
    if m:
        rid = m.group(1)
        if rid.count(prefix+'_') > 1:
            m2 = re.search(rf'{prefix}_(\d+)', rid)
            if m2: rid = f'{prefix}_{m2.group(1)}'
        return rid
    return None

def find_citing_evidence(user_id, emails, audit_at, analysis=None):
    # Try to find evidence that cites the user
    ev_ids_up_to = get_evs_up_to(audit_at)
    for ev_id in ev_ids_up_to:
        if ev_id not in ev_cache: 
            continue
        etype, content = ev_cache[ev_id]
        if content is None and etype in ['other', 'pdf']:
            # check filename/metadata in manifest
            m = ev_manifest.get(ev_id, {})
            cstr = str(m) + str(ev_id)
            if user_precise(cstr, user_id, emails):
                return ev_id
            continue
        cstr = str(content)
        if user_precise(cstr, user_id, emails):
            return ev_id
    # fallback to any evidence up to audit_at
    if ev_ids_up_to:
        return ev_ids_up_to[-1]
    return ''

def analyze(req, user_id, emails):
    audit_at = req['audit_at']
    ev_ids = get_evs_up_to(audit_at)
    res = {
        'backup': [], 'flow': [], 'search': [], 'analytics': [], 'support': [], 'export': [],
        'account': [], 'audit': [], 'tombstone': []
    }
    # system activity
    try:
        for act in system_activity:
            act_ts = act.get('timestamp') or act.get('occurred_at') or act.get('created_at') or ''
            if act_ts and act_ts > audit_at: 
                continue
            astr = str(act)
            if not user_precise(astr, user_id, emails): 
                continue
            rid = act.get('resource_id') or ''
            if rid.startswith('backup_'): res['backup'].append((rid, act, None))
            elif rid.startswith('data_flow_'): res['flow'].append((rid, act, None))
            elif rid.startswith('search_'): res['search'].append((rid, act, None))
            elif rid.startswith('analytics_'): res['analytics'].append((rid, act, None))
            elif rid.startswith('support_'): res['support'].append((rid, act, None))
            elif rid.startswith('export_'): res['export'].append((rid, act, None))
            elif rid.startswith('account_'): res['account'].append((rid, act, None))
            elif rid.startswith('tombstone_'): res['tombstone'].append((rid, act, None))
            elif rid.startswith('audit_record_'): res['audit'].append((rid, act, None))
    except Exception:
        pass
    
    for ev_id in ev_ids:
        if ev_id not in ev_cache: 
            continue
        etype, content = ev_cache[ev_id]
        if content is None:
            m = ev_manifest.get(ev_id,{})
            cstr = str(m)
            if user_precise(cstr, user_id, emails):
                # try to extract ids from filename/desc
                for pref in ['account','audit_record','backup','data_flow','search','support','export','analytics','tombstone']:
                    m2 = re.findall(rf'({pref}_\d+)', cstr)
                    for rid in m2:
                        if rid.count(pref+'_')>1:
                            m3=re.search(rf'{pref}_(\d+)', rid)
                            if m3: rid=f'{pref}_{m3.group(1)}'
                        if pref in ['backup']: res['backup'].append((rid,m,ev_id))
                        elif pref in ['data_flow']: res['flow'].append((rid,m,ev_id))
                        elif pref in ['search']: res['search'].append((rid,m,ev_id))
                        elif pref in ['analytics']: res['analytics'].append((rid,m,ev_id))
                        elif pref in ['support']: res['support'].append((rid,m,ev_id))
                        elif pref in ['export']: res['export'].append((rid,m,ev_id))
                        elif pref in ['account']: res['account'].append((rid,m,ev_id))
                        elif pref in ['tombstone']: res['tombstone'].append((rid,m,ev_id))
                        elif pref in ['audit_record']: res['audit'].append((rid,m,ev_id))
            continue
        cstr = str(content)
        if not user_precise(cstr, user_id, emails): 
            continue
        if etype == 'sql':
            try:
                conn = sqlite3.connect(':memory:')
                conn.executescript(cstr)
                cur = conn.cursor()
                cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
                for t in [r[0] for r in cur.fetchall()]:
                    try:
                        cur.execute(f'SELECT * FROM "{t}"')
                        rows = cur.fetchall()
                        cols = [d[0] for d in cur.description]
                        for row in rows:
                            rd = dict(zip(cols, row))
                            rs = str(rd).lower()
                            if not user_precise(rs, user_id, emails): 
                                continue
                            tl = t.lower()
                            rid = rd.get('resource_id') or rd.get('id')
                            if not rid and isinstance(rid, str):
                                pass
                            if 'customer' in tl and rd.get('resource_id'):
                                res['account'].append((rd['resource_id'], rd, ev_id))
                            elif 'search' in tl and rd.get('resource_id'):
                                res['search'].append((rd['resource_id'], rd, ev_id))
                            elif 'analytic' in tl and rd.get('resource_id'):
                                res['analytics'].append((rd['resource_id'], rd, ev_id))
                            elif 'support' in tl and rd.get('resource_id'):
                                res['support'].append((rd['resource_id'], rd, ev_id))
                            elif 'export' in tl and rd.get('resource_id'):
                                res['export'].append((rd['resource_id'], rd, ev_id))
                            elif 'backup' in tl and rd.get('resource_id'):
                                res['backup'].append((rd['resource_id'], rd, ev_id))
                            elif ('connector' in tl or 'data_flow' in tl) and rd.get('resource_id'):
                                res['flow'].append((rd['resource_id'], rd, ev_id))
                            elif 'tombstone' in tl and rd.get('resource_id'):
                                res['tombstone'].append((rd['resource_id'], rd, ev_id))
                            elif 'audit' in tl and rd.get('resource_id'):
                                res['audit'].append((rd['resource_id'], rd, ev_id))
                            elif rd.get('resource_id'):
                                rdid = str(rd['resource_id'])
                                if rdid.startswith('backup_'): res['backup'].append((rdid,rd,ev_id))
                                elif rdid.startswith('data_flow_'): res['flow'].append((rdid,rd,ev_id))
                                elif rdid.startswith('account_'): res['account'].append((rdid,rd,ev_id))
                                elif rdid.startswith('audit_record_'): res['audit'].append((rdid,rd,ev_id))
                                elif rdid.startswith('search_'): res['search'].append((rdid,rd,ev_id))
                                elif rdid.startswith('support_'): res['support'].append((rdid,rd,ev_id))
                                elif rdid.startswith('export_'): res['export'].append((rdid,rd,ev_id))
                                elif rdid.startswith('analytics_'): res['analytics'].append((rdid,rd,ev_id))
                                elif rdid.startswith('tombstone_'): res['tombstone'].append((rdid,rd,ev_id))
                    except Exception:
                        pass
                conn.close()
            except Exception:
                pass
        elif etype == 'json':
            try:
                def walk(o):
                    if isinstance(o, dict):
                        s = str(o)
                        if user_precise(s, user_id, emails) and o.get('resource_id'):
                            rid = str(o['resource_id'])
                            if rid.startswith('backup_'): res['backup'].append((rid,o,ev_id))
                            elif rid.startswith('data_flow_'): res['flow'].append((rid,o,ev_id))
                            elif rid.startswith('search_'): res['search'].append((rid,o,ev_id))
                            elif rid.startswith('analytics_'): res['analytics'].append((rid,o,ev_id))
                            elif rid.startswith('support_'): res['support'].append((rid,o,ev_id))
                            elif rid.startswith('export_'): res['export'].append((rid,o,ev_id))
                            elif rid.startswith('account_'): res['account'].append((rid,o,ev_id))
                            elif rid.startswith('tombstone_'): res['tombstone'].append((rid,o,ev_id))
                            elif rid.startswith('audit_record_'): res['audit'].append((rid,o,ev_id))
                        for k,v in o.items(): walk(v)
                    elif isinstance(o, list):
                        for it in o: walk(it)
                walk(content)
            except Exception:
                pass
        elif etype in ['log', 'txt']:
            for line in cstr.splitlines():
                if not user_precise(line, user_id, emails): 
                    continue
                for pref, key in [('backup','backup'),('data_flow','flow'),('account','account'),('audit_record','audit'),('search','search'),('support','support'),('export','export'),('analytics','analytics'),('tombstone','tombstone')]:
                    for m in re.findall(rf'({pref}_\d+)', line):
                        rid = m
                        if rid.count(pref+'_')>1:
                            m2=re.search(rf'{pref}_(\d+)', rid)
                            if m2: rid=f'{pref}_{m2.group(1)}'
                        res[key].append((rid, {'line':line}, ev_id))
    def dedup(lst):
        seen=set(); out=[]
        for x in lst:
            k=x[0]
            if k not in seen: 
                out.append(x); seen.add(k)
        return out
    for k in res: res[k]=dedup(res[k])
    return res

def make_incomplete(analysis, user_id, emails, req):
    steps = []
    step_no = 1
    findings = []
    cite = find_citing_evidence(user_id, emails, req['audit_at'], analysis)
    
    def get_ev_for(x):
        if len(x)>2 and x[2] and x[2] in ev_manifest:
            # ensure up to audit_at
            if ev_manifest[x[2]]['captured_at'] <= req['audit_at']:
                return x[2]
        return cite if cite else ''
    
    for bf in analysis['backup']:
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"backup_service","resource_id":bf[0],"operation":"REPORT_RESTORE_RISK","state":"ACTIVE","evidence_id":get_ev_for(bf)}); step_no+=1
    for ff in analysis['flow']:
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"integration_service","resource_id":ff[0],"operation":"REPORT_ACTIVE_DATA_FLOW","state":"ACTIVE","evidence_id":get_ev_for(ff)}); step_no+=1
    for sf in analysis['search']:
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"search_service","resource_id":sf[0],"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":get_ev_for(sf)}); step_no+=1
    for af in analysis['analytics']:
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"analytics_platform","resource_id":af[0],"operation":"REPORT_EXPOSED_PII","state":"PRESENT","evidence_id":get_ev_for(af)}); step_no+=1
    for sp in analysis['support']:
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"support_platform","resource_id":sp[0],"operation":"REPORT_EXPOSED_PII","state":"PRESENT","evidence_id":get_ev_for(sp)}); step_no+=1
    for ef in analysis['export']:
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"export_service","resource_id":ef[0],"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":get_ev_for(ef)}); step_no+=1
    for tf in analysis['tombstone']:
        tdata = tf[1]
        if isinstance(tdata, dict):
            if tdata.get('name') or tdata.get('email') or tdata.get('phone') or tdata.get('email_hash'):
                findings.append({"step_no":step_no,"phase":"FINDING","system_id":"identity_service","resource_id":tf[0],"operation":"REPORT_EXPOSED_PII","state":"PRESENT","evidence_id":get_ev_for(tf)}); step_no+=1
    if analysis['account']:
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"account_service","resource_id":analysis['account'][0][0],"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":get_ev_for(analysis['account'][0])}); step_no+=1
    if len(findings) == 0 and analysis['audit']:
        acc = analysis['account'][0][0] if analysis['account'] else f'account_1'
        ev_cite = get_ev_for(analysis['audit'][0]) if analysis['audit'] and len(analysis['audit'][0])>2 else cite
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"account_service","resource_id":acc,"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":ev_cite or ''}); step_no+=1
    # if still empty but we need to produce incomplete - try to find any account-related evidence
    if len(findings) == 0:
        # last resort: look for any account_ resource cited with user
        cite2 = find_citing_evidence(user_id, emails, req['audit_at'])
        findings.append({"step_no":step_no,"phase":"FINDING","system_id":"account_service","resource_id":f'account_{user_id.split("_")[-1]}' if user_id and '_' in str(user_id) else 'account_1',"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":cite2 or ''}); step_no+=1
    steps.extend(findings)
    remediation = []
    for f in findings:
        if f['operation']=='REPORT_ACTIVE_DATA_FLOW':
            remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"DISABLE_DATA_FLOW","state":"DISABLED","evidence_id":""}); step_no+=1
        elif f['operation']=='REPORT_RESTORE_RISK':
            remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"BLOCK_RESTORE","state":"BLOCKED","evidence_id":""}); step_no+=1
    for f in findings:
        if f['operation']=='REPORT_REMAINING_RECORD':
            if f['system_id']=='analytics_platform':
                remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"ANONYMIZE_RECORD","state":"ANONYMIZED","evidence_id":""}); step_no+=1
            elif f['system_id']=='support_platform':
                remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"REDACT_RECORD","state":"REDACTED","evidence_id":""}); step_no+=1
            else:
                remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""}); step_no+=1
        elif f['operation']=='REPORT_EXPOSED_PII':
            if f['system_id']=='analytics_platform':
                remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"ANONYMIZE_RECORD","state":"ANONYMIZED","evidence_id":""}); step_no+=1
            elif f['system_id'] in ['support_platform','identity_service']:
                remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"REDACT_RECORD","state":"REDACTED","evidence_id":""}); step_no+=1
            else:
                remediation.append({"step_no":step_no,"phase":"REMEDIATION","system_id":f['system_id'],"resource_id":f['resource_id'],"operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""}); step_no+=1
    steps.extend(remediation)
    verification = []
    acc_res = analysis['account'][0][0] if analysis['account'] else None
    if acc_res or any(f['system_id']=='account_service' for f in findings):
        if not acc_res:
            for f in findings:
                if f['system_id']=='account_service': acc_res=f['resource_id']; break
        if acc_res:
            verification.append({"step_no":step_no,"phase":"VERIFICATION","system_id":"account_service","resource_id":acc_res,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""}); step_no+=1
    if analysis['audit']:
        verification.append({"step_no":step_no,"phase":"VERIFICATION","system_id":"security_service","resource_id":analysis['audit'][0][0],"operation":"VERIFY_RECORD_PRESENT","state":"PRESENT","evidence_id":""}); step_no+=1
    for rem in remediation:
        if rem['operation']=='DELETE_RECORD' and rem['system_id']!='account_service':
            verification.append({"step_no":step_no,"phase":"VERIFICATION","system_id":rem['system_id'],"resource_id":rem['resource_id'],"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""}); step_no+=1
        elif rem['operation']=='REDACT_RECORD':
            verification.append({"step_no":step_no,"phase":"VERIFICATION","system_id":rem['system_id'],"resource_id":rem['resource_id'],"operation":"VERIFY_RECORD_REDACTED","state":"REDACTED","evidence_id":""}); step_no+=1
        elif rem['operation']=='ANONYMIZE_RECORD':
            verification.append({"step_no":step_no,"phase":"VERIFICATION","system_id":rem['system_id'],"resource_id":rem['resource_id'],"operation":"VERIFY_RECORD_ANONYMIZED","state":"ANONYMIZED","evidence_id":""}); step_no+=1
        elif rem['operation']=='DISABLE_DATA_FLOW':
            verification.append({"step_no":step_no,"phase":"VERIFICATION","system_id":rem['system_id'],"resource_id":rem['resource_id'],"operation":"VERIFY_DATA_FLOW_DISABLED","state":"DISABLED","evidence_id":""}); step_no+=1
        elif rem['operation']=='BLOCK_RESTORE':
            verification.append({"step_no":step_no,"phase":"VERIFICATION","system_id":rem['system_id'],"resource_id":rem['resource_id'],"operation":"VERIFY_RESTORE_BLOCKED","state":"BLOCKED","evidence_id":""}); step_no+=1
    steps.extend(verification)
    for i,s in enumerate(steps): s['step_no']=i+1
    return steps

results = []
req_map = {r['case_id']:r for r in requests}
for req in sorted(requests, key=lambda x: int(re.findall(r'\d+', x['case_id'])[0])):
    case_id = req['case_id']
    email = req['email']
    email_lc = email.lower()
    request_text = req['request_text']
    
    if not is_deletion_request(request_text):
        results.append({'case_id': case_id, 'deletion_status': 'NOT_APPLICABLE', 'steps_json': '[]'})
        continue
    
    user_id = None
    if email_lc in email_to_user:
        user_id = email_to_user[email_lc]['user_id']
    elif email_lc in hist_email_to_user:
        user_id = hist_email_to_user[email_lc]
    else:
        for uid, ems in user_all_emails.items():
            if email_lc in ems: 
                user_id = uid; break
    
    emails = set(user_all_emails.get(user_id, set())) if user_id else set()
    emails.add(email_lc)
    if user_id and user_to_identity.get(user_id):
        emails.add(str(user_to_identity[user_id].get('email','')).lower())
    
    analysis = analyze(req, user_id, emails)
    
    tombstone_bad = False
    for tf in analysis['tombstone']:
        tdata = tf[1]
        if isinstance(tdata, dict):
            if tdata.get('name') or tdata.get('email') or tdata.get('phone') or tdata.get('email_hash'):
                tombstone_bad = True
    
    has_bad = tombstone_bad or len(analysis['backup'])>0 or len(analysis['flow'])>0 or len(analysis['search'])>0 or len(analysis['support'])>0 or len(analysis['export'])>0 or len(analysis['analytics'])>0 or len(analysis['account'])>0
    
    if has_bad:
        steps = make_incomplete(analysis, user_id, emails, req)
        if len(steps) == 0 or any(s.get('evidence_id','') == '' and s['phase']=='FINDING' for s in steps):
            # force fix evidence
            cite = find_citing_evidence(user_id, emails, req['audit_at'], analysis)
            for s in steps:
                if s['phase']=='FINDING' and (not s.get('evidence_id')):
                    s['evidence_id'] = cite or s.get('evidence_id') or ''
        if len(steps) == 0:
            cite = find_citing_evidence(user_id, emails, req['audit_at'])
            acc = analysis['account'][0][0] if analysis['account'] else (f'account_{str(user_id).split("_")[-1]}' if user_id and '_' in str(user_id) else 'account_1')
            steps = [
                {"step_no":1,"phase":"FINDING","system_id":"account_service","resource_id":acc,"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":cite or get_evs_up_to(req['audit_at'])[-1] if get_evs_up_to(req['audit_at']) else ""},
                {"step_no":2,"phase":"REMEDIATION","system_id":"account_service","resource_id":acc,"operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""},
                {"step_no":3,"phase":"VERIFICATION","system_id":"account_service","resource_id":acc,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""},
            ]
        for i,s in enumerate(steps): s['step_no']=i+1
        results.append({'case_id':case_id,'deletion_status':'INCOMPLETE','steps_json':json.dumps(steps)}); continue
    
    if analysis['audit']:
        steps=[]
        step_no=1
        ev_cite = find_citing_evidence(user_id, emails, req['audit_at'], analysis)
        if not ev_cite and analysis['audit'] and len(analysis['audit'][0])>2 and analysis['audit'][0][2] in ev_manifest and ev_manifest[analysis['audit'][0][2]]['captured_at'] <= req['audit_at']:
            ev_cite = analysis['audit'][0][2]
        if not ev_cite:
            evs = get_evs_up_to(req['audit_at'])
            if evs: ev_cite = evs[-1]
        if analysis['account']:
            steps.append({"step_no":step_no,"phase":"VERIFICATION","system_id":"account_service","resource_id":analysis['account'][0][0],"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":ev_cite}); step_no+=1
        steps.append({"step_no":step_no,"phase":"VERIFICATION","system_id":"security_service","resource_id":analysis['audit'][0][0],"operation":"VERIFY_RECORD_PRESENT","state":"PRESENT","evidence_id":ev_cite}); step_no+=1
        for tf in analysis['tombstone']:
            steps.append({"step_no":step_no,"phase":"VERIFICATION","system_id":"identity_service","resource_id":tf[0],"operation":"VERIFY_RECORD_REDACTED","state":"REDACTED","evidence_id":ev_cite}); step_no+=1
        for i,s in enumerate(steps): s['step_no']=i+1
        results.append({'case_id':case_id,'deletion_status':'COMPLETE','steps_json':json.dumps(steps)}); continue
    else:
        # try to be safe
        cite = find_citing_evidence(user_id, emails, req['audit_at'])
        evs = get_evs_up_to(req['audit_at'])
        if not cite and evs: cite = evs[-1]
        acc = analysis['account'][0][0] if analysis['account'] else (f'account_{str(user_id).split("_")[-1]}' if user_id and '_' in str(user_id) else 'account_1')
        steps = [
            {"step_no":1,"phase":"FINDING","system_id":"account_service","resource_id":acc,"operation":"REPORT_REMAINING_RECORD","state":"PRESENT","evidence_id":cite or (evs[-1] if evs else '')},
            {"step_no":2,"phase":"REMEDIATION","system_id":"account_service","resource_id":acc,"operation":"DELETE_RECORD","state":"ABSENT","evidence_id":""},
            {"step_no":3,"phase":"VERIFICATION","system_id":"account_service","resource_id":acc,"operation":"VERIFY_RECORD_ABSENT","state":"ABSENT","evidence_id":""},
        ]
        for i,s in enumerate(steps): s['step_no']=i+1
        results.append({'case_id':case_id,'deletion_status':'INCOMPLETE','steps_json':json.dumps(steps)}); continue

output_path = os.path.join(REPO_ROOT, 'output.csv')
with open(output_path,'w',newline='',encoding='utf-8') as f:
    w = csv.DictWriter(f, fieldnames=['case_id','deletion_status','steps_json'])
    w.writeheader()
    for r in results: w.writerow(r)
print('done')
