import pandas as pd

df = pd.read_excel(r'C:\Users\lim\Desktop\최종.xlsx')
new_df = pd.DataFrame(
    columns=['start_time', 'last_time', 'src_flow', 'dst_flow', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port',
             'src_packet_count', 'dst_packet_count', 'src_byte_count', 'dst_byte_count', 'duration', 'land',
             'count_404', 'anomaly_url'])  # 새로운 데이터 프레임 생성

src_known_port = []
dst_known_port = []
src_ip_count = []
port_scan = []
ip_scan = []
src_byte_sum = []
dst_byte_sum = []

win_size = 100

for i in range(0, len(df)):
    print(i, '/', len(df))
    if df.loc[i, 'dst_port'] < 49152:
        dst_known_port.append(1)
    else:
        dst_known_port.append(0)
    if df.loc[i, 'src_port'] < 49152:
        src_known_port.append(1)
    else:
        src_known_port.append(0)
    if len(df) - i > win_size - 1:
        src_ip_count.append(len(df[i:i + win_size].loc[df['src_ip'] == df.loc[i, 'src_ip']]))
        port_scan.append(len(df[i:i + win_size].loc[df['src_ip'] == df.loc[i, 'src_ip']]['dst_port'].unique()))
        ip_scan.append(len(df[i:i + win_size].loc[df['src_ip'] == df.loc[i, 'src_ip']]['dst_ip'].unique()))
        src_byte_sum.append(df[i:i + win_size].loc[df['src_ip'] == df.loc[i, 'src_ip']]['src_byte_count'].sum())
        dst_byte_sum.append(df[i:i + win_size].loc[df['src_ip'] == df.loc[i, 'src_ip']]['dst_byte_count'].sum())

    else:
        src_ip_count.append(len(df[i - win_size - 1:i + 1].loc[df['src_ip'] == df.loc[i, 'src_ip']]))
        port_scan.append(len(df[i - win_size - 1:i + 1].loc[df['src_ip'] == df.loc[i, 'src_ip']]['dst_port'].unique()))
        ip_scan.append(len(df[i - win_size - 1:i + 1].loc[df['src_ip'] == df.loc[i, 'src_ip']]['dst_ip'].unique()))
        src_byte_sum.append(df[i - win_size - 1:i + 1].loc[df['src_ip'] == df.loc[i, 'src_ip']]['src_byte_count'].sum())
        dst_byte_sum.append(df[i - win_size - 1:i + 1].loc[df['src_ip'] == df.loc[i, 'src_ip']]['dst_byte_count'].sum())

df_dst_known_port = pd.DataFrame(dst_known_port, columns=['dst_known_port'])
df_src_known_port = pd.DataFrame(src_known_port, columns=['src_known_port'])
df_src_ip_count = pd.DataFrame(src_ip_count, columns=['src_ip_count'])
df_port_scan = pd.DataFrame(port_scan, columns=['port_scan'])
df_ip_scan = pd.DataFrame(ip_scan, columns=['ip_scan'])
df_src_byte_sum = pd.DataFrame(src_byte_sum, columns=['src_byte_sum'])
df_dst_byte_sum = pd.DataFrame(dst_byte_sum, columns=['dst_byte_sum'])

new_df = pd.concat([df, df_dst_known_port, df_src_known_port, df_src_ip_count, df_port_scan, df_ip_scan, df_src_byte_sum, df_dst_byte_sum], axis=1)

with pd.ExcelWriter(r'C:\Users\lim\Desktop\최종의최종.xlsx') as writer:
    new_df.to_excel(writer, index=None)
