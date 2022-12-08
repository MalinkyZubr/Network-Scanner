from numba import jit
import numpy as np
from nltk import flatten


int_str = lambda x: str(x)
@jit(nogil=True, parallel=True, debug=False)
def recursive_iteration(rnge, max_depth, start, depth=0):
    ip_list = []
    min, max = rnge
    for x in range(min, max):
        start[depth] = x
        if depth < max_depth:
            sub_list = recursive_iteration(rnge, max_depth, depth=depth+1, start=start)
            ip_list.append(sub_list)
        elif depth == max_depth:
            appender = list(map(int_str, start))
            ip_list.append(".".join(appender))
    return ip_list


def get_ips(network_ip):
    #start = prefix + [0 for x in range(octets)]
    #print(start)
    network_ip = network_ip.split(".")
    network_ip[3] = network_ip[3].split('/')
    network_ip = list(map(lambda x: int(x), flatten(network_ip)))
    octets = int(network_ip[4] / 8)
    network_ip = network_ip[:4]

    ips = flatten(recursive_iteration((0, 256), 3, network_ip, depth=octets))[1:-1]
    
    return ips


if __name__ == "__main__":
    x = get_ips('192.68.0.0/16')
    print("done")
    print(len(x))
    print(x[20000:20100])
