# Created by Gubanov Alexander (aka Derzhiarbuz) at 09.07.2019
# Contacts: derzhiarbuz@gmail.com

from zipfile import ZipFile
from pathlib import Path
import datetime


whitelist = {'195.101.2.195', '144.76.78.194'}
blacklist = {'162.252.240.124', '92.222.220.41', '173.252.226.26'}


def is_log(filepath:str):
    if len(filepath) < 4:
        return False
    if filepath[-4:] == '.log':
        return True
    else:
        return False


def get_logs(root:str):
    p = Path(root)
    logs = list(p.glob('**/*.log'))
    log_strs = []
    for pth in logs:
        log_strs.append(str(pth))
    return log_strs


def get_zips(root:str):
    p = Path(root)
    zips = list(p.glob('**/*.zip'))
    zip_strs = []
    for pth in zips:
        zip_strs.append(str(pth))
    return zip_strs


def handle_log_file(log_file, susp_dict:dict):
    prev_query = None
    line = log_file.readline()
    query = parse_query(str(line))
    while line:
        qsins = get_query_sins(query, prev_query)
        if len(qsins) >= 2:
            key = query['IP']+' '+query['query']
            if susp_dict.get(key) is None:
                susp_dict[key] = {'n': 0, 'qdict': query, 'sins': qsins}
            susp_dict[key]['n'] += 1
        prev_query = query
        line = log_file.readline()
        query = parse_query(str(line))


def parse_query(query:str):
    qdict = {}
    parts = query.split('"')
    if len(parts) < 5:
        return None
    qdict['query'] = parts[1]
    qdict['source'] = parts[3]
    qdict['client'] = parts[5]
    ipaddr = parts[0].split()
    if len(ipaddr) < 4:
        return None
    if ipaddr[0][:2] == "b'":
        qdict['IP'] = ipaddr[0][2:]
    else:
        qdict['IP'] = ipaddr[0]
    qdict['datetime'] = datetime.datetime.strptime(ipaddr[3][1:]+' '+ipaddr[4][:-1], '%d/%b/%Y:%H:%M:%S %z')
    codes = parts[2].split()
    if len(codes) < 2:
        return None
    qdict['code'] = int(codes[0])
    qdict['size'] = int(codes[1])
    return qdict


def get_query_sins(qdict: dict, prevqdict = None):
    global whitelist
    global blacklist
    sins = set()

    if qdict['IP'] in whitelist:
        return sins

    if qdict['IP'] in blacklist:
        sins.add('Blacklist')

    if len(qdict['query']) >= 8 and qdict['query'][:8] == 'PROPFIND':
        sins.add('PROPFIND')

    if qdict['client'].find('Mozilla') == -1:
        sins.add('No Mozilla')

    if qdict['query'].find('.js') >= 0:
        sins.add('.js (javasript sin)')

    if prevqdict:
        if qdict['IP'] == prevqdict['IP'] and (qdict['datetime'].timestamp() - prevqdict['datetime'].timestamp()) < 0.3:
            sins.add('Frequency')

    return sins


if __name__ == '__main__':

    root_dir = 'Logs/'
    susp_dict = {}

    print('Logs: ' + str(get_logs(root_dir)))
    for log_path in get_logs(root_dir):
        with open(log_path) as lfile:
            handle_log_file(lfile, susp_dict)

    print('Zips: ' + str(get_zips(root_dir)))

    for zipname in get_zips(root_dir):
        zf = ZipFile(zipname, 'r')
        print('in ' + zipname + ' ' + str(zf.namelist()))
        for zfile_path in zf.namelist():
            if is_log(zfile_path):
                with zf.open(zfile_path) as zfile:
                    handle_log_file(zfile, susp_dict)

    susp_list = list(susp_dict.values())
    susp_list.sort(key=lambda x: x['n'], reverse=True)
    for v in susp_list:
        print(str(v['n']) + '  ' + str(v['sins']) + '  ' + str(v['qdict']))