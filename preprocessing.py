import numpy as np
import pandas as pd
from datetime import timedelta
import time

# 테스트 데이터 불러오기
test = pd.read_csv(r'C:\Users\lim\Downloads\KISA-challenge2019-Network_trainset\('
                   r'참고)network_train_set1_분할\network_train_set1_00000.csv',
                   sep=',', error_bad_lines=False)
test = test.dropna(subset=['ip.src', 'ip.dst'])  # 출발지/도착지 IP가 없으면 삭제함
protocol_list = ['TCP', 'HTTP/XML', 'DNS', 'SMB', 'SMB2', 'ICMP', 'NTP', 'HTTP', 'UDP', 'TLSv1.2', 'SSH', 'SSHv2',
                 'FTP', 'FTP-DATA', 'TLSv1', 'SSLv3', 'SSL', 'SSLv2', 'RPC_NETLOGON', 'DCERPC', 'EPM', 'SMB', 'SMB2',
                 'KRB5', 'LDAP', 'DRSUAPI', 'NBSS', 'LANMAN', 'LSARPC', 'PKIX-CRL', 'SRVSVC', 'OCSP', 'TLSv1.1', 'MP4',
                 'TLSv1.3', 'OpcUa', 'WebSocket', 'SAMR', 'BROWSER', 'BJNP', 'SSDP', 'GQUIC', 'STUN', 'Elasticsearch',
                 'UDPENCAP']
udp_list = ['ICMP', 'NTP', 'BROWSER', 'BJNP', 'SSDP', 'GQUIC', 'STUN', 'Elasticsearch', 'UDPENCAP']
error_session = []
# 허용할 프로토콜 리스트
# 잘 불러왔는 지 확인
print(test['_ws.col.Protocol'].unique())
print(test.columns)


# 함수 리스트
def service(ddf):
    service_list = ddf['_ws.col.Protocol'].unique()
    if 'HTTP' in service_list:
        return 'HTTP'
    elif 'TLSv1.2' in service_list:
        return 'TLSv1.2'
    elif 'TLSv1' in service_list:
        return 'TLSv1'
    elif 'SSLv3' in service_list:
        return 'SSLv3'
    elif 'SSL' in service_list:
        return 'SSL'
    elif 'HTTP/XML' in service_list:
        return 'HTTP/XML'
    elif 'FTP' in service_list:
        return 'FTP'
    elif 'RPC_NETLOGON' in service_list:
        return 'RPC_NETLOGON'
    elif 'DCERPC' in service_list:
        return 'DCERPC'
    elif 'EPM' in service_list:
        return 'EPM'
    elif 'SMB' in service_list:
        return 'SMB'
    elif 'SMB2' in service_list:
        return 'SMB2'
    elif 'KRB5' in service_list:
        return 'KRB5'
    elif 'LDAP' in service_list:
        return 'LDAP'
    elif 'DRSUAPI' in service_list:
        return 'DRSUAPI'
    elif 'NBSS' in service_list:
        return 'NBSS'
    elif 'LANMAN' in service_list:
        return 'LANMAN'
    elif 'LSARPC' in service_list:
        return 'LSARPC'
    elif 'PKIX-CRL' in service_list:
        return 'PKIX-CRL'
    elif 'SRVSVC' in service_list:
        return 'SRVSVC'
    elif 'SSH' in service_list:
        return 'SSH'
    elif 'SSHv2' in service_list:
        return 'SSHv2'
    elif 'FTP-DATA' in service_list:
        return 'FTP-DATA'
    elif 'OCSP' in service_list:
        return 'OCSP'
    elif 'TLSv1.1' in service_list:
        return 'TLSv1.1'
    elif 'MP4' in service_list:
        return 'MP4'
    elif 'TLSv1.3' in service_list:
        return 'TLSv1.3'
    elif 'SSLv2' in service_list:
        return 'SSLv2'
    elif 'OpcUa' in service_list:
        return 'OpcUa'
    elif 'WebSocket' in service_list:
        return 'WebSocket'
    elif 'SAMR' in service_list:
        return 'SAMR'
    else:
        return ddf.loc[0, '_ws.col.Protocol']


def src_packet_count(ddf):
    ssrc_ip = ddf.loc[0, 'ip.src']
    return len(ddf.loc[ddf['ip.src'] == ssrc_ip])


def dst_packet_count(ddf):
    ddst_ip = ddf.loc[0, 'ip.dst']
    return len(ddf.loc[ddf['ip.src'] == ddst_ip])


def src_byte_count(ddf):
    unique = ddf['_ws.col.Protocol'].unique()
    if len(unique) > 1:
        unique = unique[1]
    ssrc_ip = ddf.loc[0, 'ip.src']
    if (unique in udp_list) | (unique in ['UDP', 'DNS']):
        return ddf.loc[ddf['ip.src'] == ssrc_ip]['udp.length'].sum()
    else:
        return ddf.loc[ddf['ip.src'] == ssrc_ip]['tcp.len'].sum()


def dst_byte_count(ddf):
    unique = ddf['_ws.col.Protocol'].unique()
    if len(unique) > 1:
        unique = unique[1]
    ddst_ip = ddf.loc[0, 'ip.dst']
    if (unique in udp_list) | (unique in ['UDP', 'DNS']):
        return ddf.loc[ddf['ip.src'] == ddst_ip]['udp.length'].sum()
    else:
        return ddf.loc[ddf['ip.src'] == ddst_ip]['tcp.len'].sum()


def duration(ddf):
    sstart_time = ddf.loc[0, '_ws.col.UTCtime']
    end_time = ddf.loc[ddf.tail(1).index.item(), '_ws.col.UTCtime']
    ddelta = timedelta(hours=int(sstart_time[0:2]), minutes=int(sstart_time[3:5]), seconds=int(sstart_time[6:8]))
    ddelta2 = timedelta(hours=int(end_time[0:2]), minutes=int(end_time[3:5]), seconds=int(end_time[6:8]))
    return ddelta2.seconds - ddelta.seconds


def land(ddf):
    if ddf.loc[0, 'ip.src'] == ddf.loc[0, 'ip.dst']:
        return 1
    else:
        return 0


def flow(ddf):
    ssrc_ip = list(map(int, ddf.loc[0, 'ip.src'].split('.')))
    if (ssrc_ip[0] == 192) & (ssrc_ip[1] == 168):
        src_flow = '내부'
    elif (ssrc_ip[0] == 172) & ((ssrc_ip[1] >= 16) & (ssrc_ip[1] <= 31)):
        src_flow = '내부'
    elif ssrc_ip[0] == 10:
        src_flow = '내부'
    else:
        src_flow = '외부'
    if src_flow == '내부':
        return 0
    else:
        return 1

def flow2(ddf):
    ddst_ip = list(map(int, ddf.loc[0, 'ip.dst'].split('.')))
    if (ddst_ip[0] == 192) & (ddst_ip[1] == 168):
        dst_flow = '내부'
    elif (ddst_ip[0] == 172) & ((ddst_ip[1] >= 16) & (ddst_ip[1] <= 31)):
        dst_flow = '내부'
    elif ddst_ip[0] == 10:
        dst_flow = '내부'
    else:
        dst_flow = '외부'
    if dst_flow == '내부':
        return 0
    else:
        return 1

def error_check2(nnew_df, ddf):
    if ddf.loc[0, '_ws.col.Protocol'] in ['UDP', 'DNS']:
        a = nnew_df.loc[(nnew_df['src_ip'] == ddf.loc[0, 'ip.src']) & (nnew_df['dst_ip'] == ddf.loc[0, 'ip.dst']) & (
                nnew_df['src_port'] == ddf.loc[0, 'udp.srcport']) & (nnew_df['dst_port'] == ddf.loc[0, 'udp.dstport'])]
        b = nnew_df.loc[(nnew_df['src_ip'] == ddf.loc[0, 'ip.dst']) & (nnew_df['dst_ip'] == ddf.loc[0, 'ip.src']) & (
                nnew_df['src_port'] == ddf.loc[0, 'udp.dstport']) & (nnew_df['dst_port'] == ddf.loc[0, 'udp.srcport'])]
    elif ddf.loc[0, '_ws.col.Protocol'] == 'ICMP':
        return 0
    else:
        a = nnew_df.loc[(nnew_df['src_ip'] == ddf.loc[0, 'ip.src']) & (nnew_df['dst_ip'] == ddf.loc[0, 'ip.dst']) & (
                nnew_df['src_port'] == ddf.loc[0, 'tcp.srcport']) & (nnew_df['dst_port'] == ddf.loc[0, 'tcp.dstport'])]
        b = nnew_df.loc[(nnew_df['src_ip'] == ddf.loc[0, 'ip.dst']) & (nnew_df['dst_ip'] == ddf.loc[0, 'ip.src']) & (
                nnew_df['src_port'] == ddf.loc[0, 'tcp.dstport']) & (nnew_df['dst_port'] == ddf.loc[0, 'tcp.srcport'])]
    if len(a) + len(b) > 1:
        return 1
    else:
        return 0


def count_404(ddf):
    return len(ddf.loc[(ddf['http.response.code'] > 400) & (ddf['http.response.code'] < 500)])


def anomaly_url(ddf):
    return 0


start = time.time()
test = test[test['_ws.col.Protocol'].isin(protocol_list)].reset_index(drop=True)  # 허용 프로토콜 외 모두 삭제
df = test[test['_ws.col.Protocol'].isin(protocol_list)].reset_index(drop=True)
new_df = pd.DataFrame(
    columns=['start_time', 'last_time', 'src_flow', 'dst_flow', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
             'src_packet_count', 'dst_packet_count', 'src_byte_count', 'dst_byte_count', 'duration', 'land',
             'count_404', 'anomaly_url'])  # 새로운 데이터 프레임 생성
new_df_list = []

win_size = 50000
k = round(len(df) / win_size)
df_list = []
for i in range(0, k + 1):
    df_list.append(df[i * win_size:(i * win_size) + win_size])

while len(df_list[0]) != 0:
    src_ip = df_list[0].loc[0, 'ip.src']
    dst_ip = df_list[0].loc[0, 'ip.dst']
    src_port = df_list[0].loc[0, 'tcp.srcport']
    dst_port = df_list[0].loc[0, 'tcp.dstport']
    protocol = df_list[0].loc[0, '_ws.col.Protocol']
    # 세션 기준으로 트래킹

    if df_list[0].loc[0, '_ws.col.Protocol'] in udp_list:
        session = df_list[0].loc[((df_list[0]['ip.src'] == src_ip) & (df_list[0]['ip.dst'] == dst_ip) & (
            (df_list[0]['_ws.col.Protocol'] == df_list[0].loc[0, '_ws.col.Protocol']))) | (
                                         (df_list[0]['ip.dst'] == src_ip) & (df_list[0]['ip.src'] == dst_ip) & (
                                     (df_list[0]['_ws.col.Protocol'] == df_list[0].loc[0, '_ws.col.Protocol'])))]
        j = 0
        for index, row in session.iterrows():
            if index == 0:
                j = index
            else:
                delta = timedelta(hours=int(df_list[0].loc[j, '_ws.col.UTCtime'][0:2]),
                                  minutes=int(df_list[0].loc[j, '_ws.col.UTCtime'][3:5]),
                                  seconds=int(df_list[0].loc[j, '_ws.col.UTCtime'][6:8]))
                delta2 = timedelta(hours=int(df_list[0].loc[index, '_ws.col.UTCtime'][0:2]),
                                   minutes=int(df_list[0].loc[index, '_ws.col.UTCtime'][3:5]),
                                   seconds=int(df_list[0].loc[index, '_ws.col.UTCtime'][6:8]))
                if delta2.seconds - delta.seconds >= 10:
                    session = session.loc[0:j]
                    break
                j = index
    elif np.isnan(src_port):
        src_port = df_list[0].loc[0, 'udp.srcport']
        dst_port = df_list[0].loc[0, 'udp.dstport']
        session = df_list[0].loc[((df_list[0]['ip.src'] == src_ip) & (df_list[0]['udp.srcport'] == src_port) & (
                df_list[0]['ip.dst'] == dst_ip) & (df_list[0]['udp.dstport'] == dst_port)) | (
                                         (df_list[0]['ip.dst'] == src_ip) & (df_list[0]['ip.src'] == dst_ip) & (
                                         df_list[0]['udp.srcport'] == dst_port) & (
                                                 df_list[0]['udp.dstport'] == src_port))]
    else:
        session = df_list[0].loc[((df_list[0]['ip.src'] == src_ip) & (df_list[0]['tcp.srcport'] == src_port) & (
                df_list[0]['ip.dst'] == dst_ip) & (df_list[0]['tcp.dstport'] == dst_port)) | (
                                         (df_list[0]['ip.dst'] == src_ip) & (df_list[0]['ip.src'] == dst_ip) & (
                                         df_list[0]['tcp.srcport'] == dst_port) & (
                                                 df_list[0]['tcp.dstport'] == src_port))]

    start_time = session.loc[0, '_ws.col.UTCtime']
    last_time = session.loc[session.tail(1).index.item(), '_ws.col.UTCtime']
    new_df.loc[len(new_df)] = [start_time, last_time, flow(session), flow2(session), service(session), src_ip, src_port, dst_ip,
                               dst_port, src_packet_count(session), dst_packet_count(session), src_byte_count(session),
                               dst_byte_count(session), duration(session), land(session), count_404(session),
                               anomaly_url(session)]
    df_list[0] = df_list[0].drop(session.index, 0)
    df_list[0] = df_list[0].reset_index(drop=True)
    # 짤린 세션
    if error_check2(new_df, session):
        if (len(new_df[((new_df['src_ip'] == new_df.tail(1)['src_ip'].item()) & (
                new_df['src_port'] == new_df.tail(1)['src_port'].item()) & (
                                new_df['dst_ip'] == new_df.tail(1)['dst_ip'].item()) & (
                                new_df['dst_port'] == new_df.tail(1)['dst_port'].item()))])) == 2:
            e_index = new_df[((new_df['src_ip'] == new_df.tail(1)['src_ip'].item()) & (
                    new_df['src_port'] == new_df.tail(1)['src_port'].item()) & (
                                      new_df['dst_ip'] == new_df.tail(1)['dst_ip'].item()) & (
                                      new_df['dst_port'] == new_df.tail(1)['dst_port'].item()))].head(
                1).index.item()
            new_df.loc[e_index, 'src_packet_count'] = new_df.loc[e_index, 'src_packet_count'] + new_df.tail(1)[
                'src_packet_count'].item()
            new_df.loc[e_index, 'dst_packet_count'] = new_df.loc[e_index, 'dst_packet_count'] + new_df.tail(1)[
                'dst_packet_count'].item()
            new_df.loc[e_index, 'src_byte_count'] = new_df.loc[e_index, 'src_byte_count'] + new_df.tail(1)[
                'src_byte_count'].item()
            new_df.loc[e_index, 'dst_byte_count'] = new_df.loc[e_index, 'dst_byte_count'] + new_df.tail(1)[
                'dst_byte_count'].item()
            new_df.loc[e_index, 'last_time'] = new_df.tail(1)['last_time'].item()
            new_df.loc[e_index, 'count_404'] = new_df.loc[e_index, 'count_404'] + new_df.tail(1)['count_404'].item()
            new_df.loc[e_index, 'anomaly_url'] = new_df.loc[e_index, 'anomaly_url'] + new_df.tail(1)[
                'anomaly_url'].item()

            e_delta = timedelta(hours=int(new_df.loc[e_index, 'start_time'][0:2]),
                                minutes=int(new_df.loc[e_index, 'start_time'][3:5]),
                                seconds=int(new_df.loc[e_index, 'start_time'][6:8]))
            e_delta2 = timedelta(hours=int(new_df.tail(1)['last_time'].item()[0:2]),
                                 minutes=int(new_df.tail(1)['last_time'].item()[3:5]),
                                 seconds=int(new_df.tail(1)['last_time'].item()[6:8]))
            new_df.loc[e_index, 'duration'] = e_delta2.seconds - e_delta.seconds
            new_df = new_df.drop(len(new_df) - 1, 0)
        else:
            e_index = new_df[((new_df['src_ip'] == new_df.tail(1)['dst_ip'].item()) & (
                    new_df['src_port'] == new_df.tail(1)['dst_port'].item()) & (
                                      new_df['dst_ip'] == new_df.tail(1)['src_ip'].item()) & (
                                      new_df['dst_port'] == new_df.tail(1)['src_port'].item()))].head(
                1).index.item()
            new_df.loc[e_index, 'src_packet_count'] = new_df.loc[e_index, 'src_packet_count'] + new_df.tail(1)[
                'dst_packet_count'].item()
            new_df.loc[e_index, 'dst_packet_count'] = new_df.loc[e_index, 'dst_packet_count'] + new_df.tail(1)[
                'src_packet_count'].item()
            new_df.loc[e_index, 'src_byte_count'] = new_df.loc[e_index, 'src_byte_count'] + new_df.tail(1)[
                'dst_byte_count'].item()
            new_df.loc[e_index, 'dst_byte_count'] = new_df.loc[e_index, 'dst_byte_count'] + new_df.tail(1)[
                'src_byte_count'].item()
            new_df.loc[e_index, 'last_time'] = new_df.tail(1)['last_time'].item()
            new_df.loc[e_index, 'count_404'] = new_df.loc[e_index, 'count_404'] + new_df.tail(1)['count_404'].item()
            new_df.loc[e_index, 'anomaly_url'] = new_df.loc[e_index, 'anomaly_url'] + new_df.tail(1)[
                'anomaly_url'].item()

            e_delta = timedelta(hours=int(new_df.loc[e_index, 'start_time'][0:2]),
                                minutes=int(new_df.loc[e_index, 'start_time'][3:5]),
                                seconds=int(new_df.loc[e_index, 'start_time'][6:8]))
            e_delta2 = timedelta(hours=int(new_df.tail(1)['last_time'].item()[0:2]),
                                 minutes=int(new_df.tail(1)['last_time'].item()[3:5]),
                                 seconds=int(new_df.tail(1)['last_time'].item()[6:8]))
            new_df.loc[e_index, 'duration'] = e_delta2.seconds - e_delta.seconds
            new_df = new_df.drop(len(new_df) - 1, 0)
    # print(len(new_df))
    if (len(df_list[0]) < win_size + win_size / 2) & (len(df_list) != 1):
        df_list[0] = df_list[0].append(df_list[1])
        df_list[0] = df_list[0].reset_index(drop=True)
        del df_list[1]
        print('진행중(', time.time() - start, '):', k + 1 - len(df_list), '/', k)

    if len(new_df) > 50000:
        new_df_list.append(new_df[0:45000])
        new_df = new_df[45000:]
        new_df = new_df.reset_index(drop=True)

if len(new_df_list) != 0:
    result = pd.concat(new_df_list).reset_index(drop=True)
    result = pd.concat([result, new_df]).reset_index(drop=True)
else:
    result = new_df

with pd.ExcelWriter(r'C:\Users\lim\Desktop\최종.xlsx') as writer:
    result.to_excel(writer, index=None)
