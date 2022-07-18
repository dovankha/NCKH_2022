import pydivert
import re
import pickle
import warnings

warnings.filterwarnings("ignore")


# load = pickle.load(open('phishing.pkl','rb'))


def check_format_URL(url):
    return re.findall(r'(http|https):\/\/([\w\-_]+(?:(?:\.[\w\-_]+)+))([\w\-\.,@?^=%&:/~\+#]*[\w\-\@?^=%&/~\+#])?', url)


def check_format_url(url):
    regex = r"(?i)\b(^(?:http(s)?:\/\/)?[\w.-]+(?:\.[\w\.-]+)+[\w\-\._~:/?#[\]@!\$&'\(\)\*\+,;=.]+$)"
    return re.compile(regex).match(url)


# def extract_url_http(payload_tcp):
#     start_string='Host: '
#     end_string='\r\nConnection'
#     start_index = payload_tcp.find(start_string.encode())
#     end_index = payload_tcp.find(end_string.encode())
#     host = payload_tcp[start_index+6:end_index]

#     start_string ='GET '
#     end_string = ' HTTP'
#     start_index=payload_tcp.find(start_string.encode())
#     end_index=payload_tcp.find(end_string.encode())
#     path =payload_tcp[start_index+4:end_index]
#     url = host+path
#     url1 = 'http://' + url.decode('utf-8')
#     if len(url)!=0 and check_format_URL(url1) :
#         return (url1)


def extract_url_http(payload_tcp):
    start_string = 'Host: '
    end_string = '\r\nConnection'
    start_index = payload_tcp.find(start_string.encode())
    end_index = payload_tcp.find(end_string.encode())
    host = payload_tcp[start_index + 6:end_index]

    start_string = 'GET '
    end_string = ' HTTP'
    start_index = payload_tcp.find(start_string.encode())
    end_index = payload_tcp.find(end_string.encode())
    path = payload_tcp[start_index + 4:end_index]
    url = host + path
    url1 = 'http://' + url.decode('utf-8')
    if len(url) != 0 and check_format_url(url.decode()):
        url = url.decode()
        return url
    return ""


# def extract_url(payload_tcp, dst_port):
#     if dst_port == 80:
#         extract_url_http(payload_tcp)
#         #print ("pass")
#     # if dst_port == 443:
#     #     return extract_url_https(payload_tcp)


# def extract_url_https(payload_tcp):
#     start_index = 127
#     end_string = '\x00\x17'

#     end_index = payload_tcp.find(end_string.encode('utf-8'), start_index)
#     url = payload_tcp[start_index:end_index]
#     url1 = 'https://' + url.decode('utf-8', 'backslashreplace')
#     if len(url)!=0 and check_format_URL(url1) :
#         return (url1)

def extract_url_https(payload_tcp):
    start_index = 127
    end_string = '\x00\x17'

    end_index = payload_tcp.find(end_string.encode('utf-8'), start_index)
    url = payload_tcp[start_index:end_index]
    if len(url) != 0 and check_format_url(url.decode('utf-8', 'backslashreplace')):
        url = url.decode('utf-8', 'backslashreplace')
        return url
    return ""


def extract_url(payload_tcp, dst_port):
    if dst_port == 80:
        return extract_url_http(payload_tcp)
    if dst_port == 443:
        return extract_url_https(payload_tcp)


with pydivert.WinDivert("(tcp.DstPort == 80 or tcp.DstPort == 443) and tcp.PayloadLength > 0") as w:
    for packet in w:
        if extract_url(packet.tcp.payload, packet.dst_port) == "":
            pass
        else:
            # if(load.predict([extract_url(packet.tcp.payload, packet.dst_port)])== "bad"):
            print(extract_url(packet.tcp.payload, packet.dst_port))
        w.send(packet)
