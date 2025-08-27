
#!/usr/bin/env python3
import sys, csv, json, re, argparse, os

PHONE_RE = re.compile(r'\b(\d{10})\b')
AADHAR_RE = re.compile(r'\b(\d{12})\b')
PASSPORT_RE = re.compile(r'\b([A-Z]{1}\d{7})\b', re.I)  # common format like P1234567
EMAIL_RE = re.compile(r'\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')
UPI_RE = re.compile(r'\b([A-Za-z0-9._%-]{2,})@([A-Za-z0-9]{2,})\b', re.I)  # simple upi pattern
IPV4_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
DEVICE_RE = re.compile(r'\b([A-Za-z0-9\-:_]{8,})\b')

def mask_phone(p):
    s = re.sub(r'\D', '', str(p))
    if len(s) == 10:
        return s[:2] + 'XXXXXX' + s[-2:]
    return '[REDACTED_PII]'

def mask_aadhar(a):
    s = re.sub(r'\D', '', str(a))
    if len(s) == 12:
        return s[:4] + 'XXXX' + s[-4:]
    return '[REDACTED_PII]'

def mask_passport(p):
    m = PASSPORT_RE.search(str(p))
    if m:
        v = m.group(1)
        if len(v) >= 4:
            return v[0] + 'X'*(len(v)-2) + v[-1]
    return '[REDACTED_PII]'

def mask_email(e):
    m = EMAIL_RE.search(str(e))
    if m:
        local, domain = m.group(1), m.group(2)
        if len(local) <= 2:
            local_masked = local[0] + 'X'
        else:
            local_masked = local[:2] + 'X'*(max(3, len(local)-2))
        return local_masked + '@' + domain
    return '[REDACTED_PII]'

def mask_upi(u):
    m = UPI_RE.search(str(u))
    if m:
        user, host = m.group(1), m.group(2)
        if len(user) <= 2:
            user_masked = user[0] + 'X'
        else:
            user_masked = user[:2] + 'X'*(max(3, len(user)-2))
        return user_masked + '@' + host
    return '[REDACTED_PII]'

def mask_ip(ip):
    m = IPV4_RE.search(str(ip))
    if m:
        parts = m.group(1).split('.')
        if len(parts) == 4:
            parts[-1] = 'XXX'
            return '.'.join(parts)
    return '[REDACTED_PII]'

def mask_generic_name(name):
    s = str(name).strip()
    parts = s.split()
    if len(parts) >= 2:
        out = []
        for p in parts:
            if len(p) <= 1:
                out.append('X')
            else:
                out.append(p[0] + 'X'*(len(p)-1))
        return ' '.join(out)
    return s  # don't mask single names here as per rules

def detect_and_mask(record):
    redacted = dict(record)
    standalone_found = False
    # Check A: Standalone
    phone_fields = ['phone', 'contact']
    for f in phone_fields:
        if f in record and record.get(f):
            if PHONE_RE.search(str(record[f])):
                redacted[f] = mask_phone(record[f])
                standalone_found = True
    for k,v in record.items():
        if isinstance(v, str) and PHONE_RE.search(v):
            if k not in redacted or 'X' not in str(redacted.get(k,'')):
                redacted[k] = PHONE_RE.sub(lambda m: mask_phone(m.group(1)), v)
                standalone_found = True

    for k,v in record.items():
        if isinstance(v, str) and AADHAR_RE.search(v):
            redacted[k] = AADHAR_RE.sub(lambda m: mask_aadhar(m.group(1)), v)
            standalone_found = True

    for k,v in record.items():
        if isinstance(v, str) and PASSPORT_RE.search(v):
            redacted[k] = PASSPORT_RE.sub(lambda m: mask_passport(m.group(1)), v)
            standalone_found = True

    if 'upi_id' in record and record.get('upi_id'):
        if UPI_RE.search(str(record['upi_id'])):
            redacted['upi_id'] = mask_upi(record['upi_id'])
            standalone_found = True
    else:
        for k,v in record.items():
            if isinstance(v,str) and '@' in v and UPI_RE.search(v):
                rhs = v.split('@',1)[1]
                if '.' not in rhs:
                    redacted[k] = UPI_RE.sub(lambda m: mask_upi(m.group(0)), v)
                    standalone_found = True

    email_present = False
    for k,v in record.items():
        if isinstance(v, str) and EMAIL_RE.search(v):
            email_present = True
            redacted[k] = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), v)

    name_present = False
    if (record.get('first_name') and record.get('last_name')) or (record.get('name') and len(str(record.get('name')).split())>=2):
        name_present = True
        if record.get('first_name') and record.get('last_name'):
            redacted['first_name'] = mask_generic_name(record.get('first_name'))
            redacted['last_name'] = mask_generic_name(record.get('last_name'))
        if record.get('name'):
            redacted['name'] = mask_generic_name(record.get('name'))

    address_present = False
    if record.get('address') and record.get('city') and record.get('pin_code'):
        pc = re.sub(r'\D','', str(record.get('pin_code')))
        if len(pc) >= 5:
            address_present = True
            redacted['address'] = '[REDACTED_PII_ADDRESS]'
            redacted['pin_code'] = (str(record.get('pin_code'))[:2] + 'XXX' if len(str(record.get('pin_code')))>3 else 'XXX')

    device_present = False
    if record.get('device_id') or record.get('ip_address'):
        if record.get('device_id'):
            device_present = True
            redacted['device_id'] = re.sub(r'.', 'X', str(record.get('device_id')))
        if record.get('ip_address'):
            device_present = True
            redacted['ip_address'] = mask_ip(record.get('ip_address'))

    combinatorial_count = 0
    if name_present:
        combinatorial_count += 1
    if email_present:
        combinatorial_count += 1
    if address_present:
        combinatorial_count += 1
    if device_present:
        combinatorial_count += 1

    combinatorial_pii = combinatorial_count >= 2
    is_pii = standalone_found or combinatorial_pii

    if not is_pii:
        for k,v in record.items():
            if isinstance(v, str) and EMAIL_RE.search(str(v)):
                if k in redacted:
                    redacted[k] = v
        if record.get('name') and len(str(record.get('name')).split())<2:
            redacted['name'] = record.get('name')
        if (record.get('first_name') and not record.get('last_name')) or (record.get('last_name') and not record.get('first_name')):
            if 'first_name' in redacted:
                redacted['first_name'] = record.get('first_name')
            if 'last_name' in redacted:
                redacted['last_name'] = record.get('last_name')

    if is_pii:
        for k,v in redacted.items():
            if isinstance(v,str):
                if PHONE_RE.search(v):
                    redacted[k] = PHONE_RE.sub(lambda m: mask_phone(m.group(1)), v)
                if AADHAR_RE.search(v):
                    redacted[k] = AADHAR_RE.sub(lambda m: mask_aadhar(m.group(1)), v)
                if PASSPORT_RE.search(v):
                    redacted[k] = PASSPORT_RE.sub(lambda m: mask_passport(m.group(1)), v)
                if EMAIL_RE.search(v):
                    redacted[k] = EMAIL_RE.sub(lambda m: mask_email(m.group(0)), v)
                if IPV4_RE.search(v):
                    redacted[k] = IPV4_RE.sub(lambda m: mask_ip(m.group(1)), v)

    try:
        clean = {}
        for k,v in redacted.items():
            try:
                json.dumps(v)
                clean[k]=v
            except Exception:
                clean[k]=str(v)
        return clean, bool(is_pii)
    except Exception as e:
        return redacted, bool(is_pii)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_csv', help='Input CSV path')
    parser.add_argument('--output', default='redacted_output_candidate_full_name.csv')
    args = parser.parse_args()

    inpath = args.input_csv
    outpath = args.output
    if not os.path.exists(inpath):
        print('Input file not found:', inpath)
        sys.exit(2)

    rows_out = []
    with open(inpath, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for r in reader:
            rid = r.get('record_id') or r.get('recordId') or r.get('id')
            data_json_raw = r.get('Data_json') or r.get('data_json') or r.get('Data') or r.get('data')
            if data_json_raw is None:
                redacted_json = {}
                is_pii = False
            else:
                try:
                    parsed = json.loads(data_json_raw)
                except Exception:
                    try:
                        parsed = json.loads(data_json_raw.replace("'", '"'))
                    except Exception:
                        parsed = {}
                redacted_dict, is_pii = detect_and_mask(parsed)
                redacted_json = redacted_dict
            rows_out.append({'record_id': rid, 'redacted_data_json': json.dumps(redacted_json, ensure_ascii=False), 'is_pii': str(is_pii)})

    with open(outpath, 'w', newline='', encoding='utf-8') as f:
        fieldnames = ['record_id','redacted_data_json','is_pii']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows_out:
            writer.writerow(row)

    print('Wrote', outpath)

if __name__ == '__main__':
    main()
