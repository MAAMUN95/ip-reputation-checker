import os, ipaddress, requests, streamlit as st
st.set_page_config(page_title='IP Reputation Checker', page_icon='🛡️', layout='wide')
st.title('🛡️ IP Reputation Checker')
st.caption('Check public IPs against multiple intelligence services. No result does not mean clean.')
ip=st.text_input('IP address', placeholder='172.59.195.230')
with st.sidebar:
 st.header('API keys')
 st.caption('Keys stay in this running app session. For deployment, use server-side secrets.')
 abuse_key=st.text_input('AbuseIPDB API key',type='password',value=os.getenv('ABUSEIPDB_API_KEY',''))
 vt_key=st.text_input('VirusTotal API key',type='password',value=os.getenv('VIRUSTOTAL_API_KEY',''))
 ipqs_key = st.text_input(
    'IPQualityScore API key',
    type='password',
    value=st.secrets.get('IPQUALITYSCORE_API_KEY', '')
)
 st.caption('Optional services. Their quotas and terms apply.')

def get(url,headers=None,params=None):
 try:
  r=requests.get(url,headers=headers,params=params,timeout=12)
  if r.status_code!=200: return None,f'HTTP {r.status_code}'
  return r.json(),None
 except requests.RequestException as e: return None,str(e)

if st.button('Check reputation',type='primary'):
 try:
  parsed=ipaddress.ip_address(ip.strip())
  if not parsed.is_global: st.error('Enter a globally routable public IP address.');st.stop()
 except ValueError: st.error('Enter a valid IPv4 or IPv6 address.');st.stop()
 reports=[]; scores=[]
 with st.spinner('Checking configured sources...'):
  if abuse_key:
   d,e=get('https://api.abuseipdb.com/api/v2/check',{'Key':abuse_key,'Accept':'application/json'},{'ipAddress':ip,'maxAgeInDays':90})
   if d and 'data' in d:
    x=d['data'];score=x.get('abuseConfidenceScore',0);scores.append(('AbuseIPDB',score));reports.append(('AbuseIPDB',f"Abuse confidence: {score}/100; reports: {x.get('totalReports','unknown')}; ISP: {x.get('isp','unknown')}",x))
   else: reports.append(('AbuseIPDB',f'Unavailable: {e or "Unexpected response"}',{}))
  if vt_key:
   d,e=get(f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',{'x-apikey':vt_key})
   if d and 'data' in d:
    x=d['data']['attributes']; stats=x.get('last_analysis_stats',{});reports.append(('VirusTotal',f"Malicious: {stats.get('malicious',0)}; suspicious: {stats.get('suspicious',0)}; harmless: {stats.get('harmless',0)}",x))
   else: reports.append(('VirusTotal',f'Unavailable: {e or "Unexpected response"}',{}))
  if ipqs_key:
   d,e=get(f'https://www.ipqualityscore.com/api/json/ip/{ipqs_key}/{ip}',params={'strictness':0})
   if d and d.get('success'):
    reports.append(('IPQualityScore',f"VPN: {d.get('vpn','unknown')}; proxy: {d.get('proxy','unknown')}; Tor: {d.get('tor','unknown')}; fraud score: {d.get('fraud_score','unknown')}",d))
   else: reports.append(('IPQualityScore',f'Unavailable: {e or (d or {}).get("message","Unexpected response")}',{}))
 if not reports: st.warning('Add at least one API key in the sidebar to run live checks.')
 else:
  for name,summary,details in reports:
   st.subheader(name);st.write(summary)
   with st.expander('Raw source response'):st.json(details)
  st.info('Different services measure different risks. Do not average their scores into a universal block probability. Use each source’s findings and timestamps.')
st.divider()
st.caption('For authorized security testing only. Results may be stale or incorrect; avoid automatic blocking based on a single signal.')
