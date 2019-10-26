#필수 모듈 임포트
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from datetime import timedelta
import time

#구글 드라이브 마운트
from google.colab import drive
drive.mount('/gdrive', force_remount=True)
#테스트 데이터 불러오기
test = pd.read_csv('/gdrive/My Drive/Machine Learning Datasets Repository/KISA-challenge2019-Network_trainset/network_train_set2/set2_4_00002.csv', sep=',')
test = test.dropna(subset=['ip.src', 'ip.dst'])#출발지/도착지 IP가 없으면 삭제함
protocol_list=['TCP', 'HTTP/XML','DNS', 'SMB', 'SMB2', 'ICMP', 'NTP', 'HTTP', 'UDP', 'TLSv1.2', 'SSH', 'SSHv2', 'FTP', 'FTP-DATA', 'TLSv1', 'SSLv3', 'SSL','SSLv2']
#허용할 프로토콜 리스트
#잘 불러왔는 지 확인
test['_ws.col.Protocol'].unique()

#함수 리스트
def service(df):
  service =  session['_ws.col.Protocol'].unique()
  if('HTTP' in service):
    return 'HTTP'
  elif('TLSv1.2' in service):
    return 'TLSv1.2'
  elif('TLSv1' in service):
    return 'TLSv1'
  elif('SSLv3' in service):
    return 'SSLv3'
  elif('SSL' in service):
    return 'SSL'
  elif('HTTP/XML' in service):
    return 'HTTP/XML'
  else:
    return df.loc[0, '_ws.col.Protocol']

def src_packet_count(df):
  src_ip = df.loc[0,'ip.src']
  return len(df.loc[df['ip.src']==src_ip])

def dst_packet_count(df):
  dst_ip=df.loc[0,'ip.dst']
  return len(df.loc[df['ip.src']==dst_ip])

def src_byte_count(df):
  src_ip = df.loc[0, 'ip.src']
  return df.loc[df['ip.src']==src_ip]['tcp.len'].sum()

def dst_byte_count(df):
  dst_ip = df.loc[0, 'ip.dst']
  return df.loc[df['ip.src']==dst_ip]['tcp.len'].sum()

def duration(df):
  start_time = df.loc[0, '_ws.col.UTCtime']
  end_time = df.loc[df.tail(1).index.item(),'_ws.col.UTCtime']
  delta = timedelta(hours=int(start_time[0:2]), minutes=int(start_time[3:5]), seconds = int(start_time[6:8]))
  delta2 = timedelta(hours=int(end_time[0:2]), minutes=int(end_time[3:5]), seconds = int(end_time[6:8]))
  return delta2.seconds - delta.seconds

def land(df):
  if(df.loc[0,'ip.src']==df.loc[0,'ip.dst']):
    return 1
  else:
    return 0

def flow(df):
  src_ip = list(map(int, df.loc[0,'ip.src'].split('.')))
  if((src_ip[0]==192)&(src_ip[1]==168)):
    src_flow = '내부'
  elif((src_ip[0]==172)&((src_ip[1]>=16)&(src_ip[1]<=31))):
   src_flow = '내부'
  elif(src_ip[0]==10):
    src_flow = '내부'
  else:
    src_flow = '외부'
  
  dst_ip = list(map(int, df.loc[0,'ip.dst'].split('.')))
  if((dst_ip[0]==192)&(dst_ip[1]==168)):
    dst_flow = '내부'
  elif((dst_ip[0]==172)&((dst_ip[1]>=16)&(dst_ip[1]<=31))):
    dst_flow = '내부'
  elif(dst_ip[0]==10):
    dst_flow = '내부'
  else:
    dst_flow = '외부'
  return src_flow+'->'+dst_flow

def error_check(df):
  proto_list = ['TCP', 'HTTP/XML', 'HTTP', 'TLSv1.2', 'TLSv1', 'SSLv3', 'SSL', 'SSLv2']
  if((df.loc[0,'_ws.col.Protocol'] in proto_list)&((df.loc[0, 'tcp.seq']!=0)&(df.loc[0, 'tcp.seq']!=1))):
    print('error')
    return 1
  else:
    return 0

def error_check2(df):
  #proto_list = ['TCP', 'HTTP/XML', 'HTTP', 'TLSv1.2', 'TLSv1', 'SSLv3', 'SSL', 'SSLv2']
  #a = len((new_df.loc[new_df['src_ip']==df.loc[0,'ip.src']])&(new_df.loc[new_df['src_port']==df.loc[0,'tcp.srcport']])&(new_df.loc[new_df['dst_ip']==df.loc[0,'ip.dst']])&(new_df.loc[new_df['dst_port']==df.loc[0,'tcp.dstport']]))
  #b = len((new_df.loc[new_df['src_ip']==df.loc[0,'ip.dst']])&(new_df.loc[new_df['src_port']==df.loc[0,'tcp.dstport']])&(new_df.loc[new_df['dst_ip']==df.loc[0,'ip.src']])&(new_df.loc[new_df['dst_port']==df.loc[0,'tcp.srcport']]))
  #a = len((new_df.loc[(new_df['src_ip']==df.loc[0,'ip.src'])&(new_df.loc[new_df['src_port']==df.loc[0,'tcp.srcport'])&(new_df.loc[new_df['dst_ip']==df.loc[0,'ip.dst'])&(new_df.loc[new_df['dst_port']==df.loc[0,'tcp.dstport'])))
  if(df.loc[0,'_ws.col.Protocol']=='UDP'):
    a = new_df.loc[(new_df['src_ip']==df.loc[0,'ip.src'])&(new_df['dst_ip']==df.loc[0,'ip.dst'])&(new_df['src_port']==df.loc[0,'udp.srcport'])&(new_df['dst_port']==df.loc[0,'udp.dstport'])]
    b = new_df.loc[(new_df['src_ip']==df.loc[0,'ip.dst'])&(new_df['dst_ip']==df.loc[0,'ip.src'])&(new_df['src_port']==df.loc[0,'udp.dstport'])&(new_df['dst_port']==df.loc[0,'udp.srcport'])]
  elif(df.loc[0,'_ws.col.Protocol']=='ICMP'):
    return 0
  else:
    a = new_df.loc[(new_df['src_ip']==df.loc[0,'ip.src'])&(new_df['dst_ip']==df.loc[0,'ip.dst'])&(new_df['src_port']==df.loc[0,'tcp.srcport'])&(new_df['dst_port']==df.loc[0,'tcp.dstport'])]
    b = new_df.loc[(new_df['src_ip']==df.loc[0,'ip.dst'])&(new_df['dst_ip']==df.loc[0,'ip.src'])&(new_df['src_port']==df.loc[0,'tcp.dstport'])&(new_df['dst_port']==df.loc[0,'tcp.srcport'])]
  
  if(len(a)+len(b)>1):
    print('error')
    #print(df)
    #print(a)
    #print(b)
    return 1
  else:
    return 0

start = time.time()
test = test[test['_ws.col.Protocol'].isin(protocol_list)].reset_index(drop=True)#허용 프로토콜 외 모두 삭제
df = test[test['_ws.col.Protocol'].isin(protocol_list)].reset_index(drop=True)
new_df = pd.DataFrame(columns=['time','flow', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port','src_packet_count', 'dst_packet_count', 'src_byte_count', 'dst_byte_count', 'duration', 'land'])#새로운 데이터 프레임 생성
win_size = 20000
k=round(len(df)/win_size)
df_list = []
for i in range(0, k+1):
  df_list.append(df[i*win_size:(i*win_size)+win_size])
error_session =[]

while(len(df_list[0])!=0):
  src_ip = df_list[0].loc[0,'ip.src']
  dst_ip = df_list[0].loc[0, 'ip.dst']
  src_port = df_list[0].loc[0, 'tcp.srcport']
  dst_port = df_list[0].loc[0, 'tcp.dstport']
  time = df_list[0].loc[0,'_ws.col.UTCtime']
  protocol = df_list[0].loc[0, '_ws.col.Protocol']
  #세션 기준으로 트래킹
  if(df_list[0].loc[0, '_ws.col.Protocol'] in ['ICMP', 'NTP']):
    session = df_list[0].loc[((df_list[0]['ip.src']==src_ip)&(df_list[0]['ip.dst']==dst_ip)&((df_list[0]['_ws.col.Protocol'] == 'ICMP')|(df_list[0]['_ws.col.Protocol'] == 'NTP')))|((df_list[0]['ip.dst']==src_ip)&(df_list[0]['ip.src']==dst_ip)&((df_list[0]['_ws.col.Protocol'] == 'ICMP')|(df_list[0]['_ws.col.Protocol'] == 'NTP')))]
    j=0
    for index, row in session.iterrows():
      if(index==0):
        j=index
      else:
        delta = timedelta(hours=int(df_list[0].loc[j,'_ws.col.UTCtime'][0:2]), minutes=int(df_list[0].loc[j,'_ws.col.UTCtime'][3:5]), seconds = int(df_list[0].loc[j,'_ws.col.UTCtime'][6:8]))
        delta2 = timedelta(hours=int(df_list[0].loc[index,'_ws.col.UTCtime'][0:2]), minutes=int(df_list[0].loc[index,'_ws.col.UTCtime'][3:5]), seconds = int(df_list[0].loc[index,'_ws.col.UTCtime'][6:8]))
        if(delta2.seconds-delta.seconds>=10):
          session=session.loc[0:j]
          break
        j = index
  elif(np.isnan(src_port)):
    src_port = df_list[0].loc[0, 'udp.srcport']
    dst_port = df_list[0].loc[0, 'udp.dstport']
    session = df_list[0].loc[((df_list[0]['ip.src']==src_ip)&(df_list[0]['udp.srcport']==src_port)&(df_list[0]['ip.dst']==dst_ip)&(df_list[0]['udp.dstport']==dst_port))|((df_list[0]['ip.dst']==src_ip)&(df_list[0]['ip.src']==dst_ip)&(df_list[0]['udp.srcport']==dst_port)&(df_list[0]['udp.dstport']==src_port))]
  else:
    session = df_list[0].loc[((df_list[0]['ip.src']==src_ip)&(df_list[0]['tcp.srcport']==src_port)&(df_list[0]['ip.dst']==dst_ip)&(df_list[0]['tcp.dstport']==dst_port))|((df_list[0]['ip.dst']==src_ip)&(df_list[0]['ip.src']==dst_ip)&(df_list[0]['tcp.srcport']==dst_port)&(df_list[0]['tcp.dstport']==src_port))]
  new_df.loc[len(new_df)] =[time, flow(session),service(session), src_ip, src_port, dst_ip, dst_port, src_packet_count(session), dst_packet_count(session), src_byte_count(session), dst_byte_count(session), duration(session), land(session)]
  df_list[0] = df_list[0].drop(session.index,0)
  df_list[0] = df_list[0].reset_index(drop=True)
  #print(len(df_list[0]))
  #짤린 세션
  if(error_check2(session)):
    if(len(new_df[((new_df['src_ip']==new_df.tail(1)['src_ip'].item())&(new_df['src_port']==new_df.tail(1)['src_port'].item())&(new_df['dst_ip']==new_df.tail(1)['dst_ip'].item())&(new_df['dst_port']==new_df.tail(1)['dst_port'].item()))]))==2:
      e_index = new_df[((new_df['src_ip']==new_df.tail(1)['src_ip'].item())&(new_df['src_port']==new_df.tail(1)['src_port'].item())&(new_df['dst_ip']==new_df.tail(1)['dst_ip'].item())&(new_df['dst_port']==new_df.tail(1)['dst_port'].item()))].head(1).index.item()
      new_df.loc[e_index, 'src_packet_count'] = new_df.loc[e_index, 'src_packet_count'] + new_df.tail(1)['src_packet_count'].item()
      new_df.loc[e_index, 'dst_packet_count'] = new_df.loc[e_index, 'dst_packet_count'] + new_df.tail(1)['dst_packet_count'].item()
      new_df.loc[e_index, 'src_byte_count'] = new_df.loc[e_index, 'src_byte_count'] + new_df.tail(1)['src_byte_count'].item()
      new_df.loc[e_index, 'dst_byte_count'] = new_df.loc[e_index, 'dst_byte_count'] + new_df.tail(1)['dst_byte_count'].item()
      new_df.loc[e_index, 'duration'] = new_df.loc[e_index, 'duration'] + new_df.tail(1)['duration'].item()
      new_df = new_df.drop(len(new_df)-1,0)
    else:
      e_index = new_df[((new_df['src_ip']==new_df.tail(1)['dst_ip'].item())&(new_df['src_port']==new_df.tail(1)['dst_port'].item())&(new_df['dst_ip']==new_df.tail(1)['src_ip'].item())&(new_df['dst_port']==new_df.tail(1)['src_port'].item()))].head(1).index.item()
      new_df.loc[e_index, 'src_packet_count'] = new_df.loc[e_index, 'src_packet_count'] + new_df.tail(1)['dst_packet_count'].item()
      new_df.loc[e_index, 'dst_packet_count'] = new_df.loc[e_index, 'dst_packet_count'] + new_df.tail(1)['src_packet_count'].item()
      new_df.loc[e_index, 'src_byte_count'] = new_df.loc[e_index, 'src_byte_count'] + new_df.tail(1)['dst_byte_count'].item()
      new_df.loc[e_index, 'dst_byte_count'] = new_df.loc[e_index, 'dst_byte_count'] + new_df.tail(1)['src_byte_count'].item()
      new_df.loc[e_index, 'duration'] = new_df.loc[e_index, 'duration'] + new_df.tail(1)['duration'].item()
      new_df = new_df.drop(len(new_df)-1,0)

  if((len(df_list[0])<30000)&(len(df_list)!=1)):
    df_list[0] = df_list[0].append(df_list[1])
    df_list[0] = df_list[0].reset_index(drop=True)
    del df_list[1]
    print('진행중:', k+1-len(df_list),'/',k)

print("time :", time.time() - start)
#구글 드라이브 마운트
from google.colab import drive
drive.mount('/gdrive', force_remount=True)
with pd.ExcelWriter('/gdrive/My Drive/output.xlsx') as writer:
  new_df.to_excel(writer,index=None)
