import threading
import subprocess
import sys
import re
import getopt

vulnerable = []


def check_target(target, port, verbose=False):
    global vulnerable, threadLimiter
    threadLimiter.acquire()
    print("Checking {}".format(target))
    try:
        process = subprocess.Popen("0708Detector_v2.exe -t {} -p {}".format(target, port), shell=True,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        out, err = process.communicate()
        if verbose:
            print(out.decode())
            print(err.decode())
        if "IS VULNERABLE" in out.decode():
            vulnerable.append(target)
    finally:
        threadLimiter.release()


def start(targets, port, verbose=False):
    threads = [threading.Thread(target=check_target, args=(target, port, verbose)) for target in targets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    global vulnerable
    return vulnerable


def main(argv):
    port = 3389
    targets_list = []
    target = None
    listfile = None
    verbose = False
    max_threads = 5
    global threadLimiter

    try:
        opts, args = getopt.getopt(argv[1:], 't:f:p:x:v', ['target=', 'listfile=', 'port=', 'maxthreads=', 'verbose'])
    except getopt.GetoptError:
        print("args error")
        sys.exit(1)

    for opt, arg in opts:
        if opt in ('-t', '--target'):
            target = arg
        elif opt in ('-f', '--listfile'):
            listfile = arg
        elif opt in ('-p', '--port'):
            port = arg
        elif opt in ('-x', '--maxthreads'):
            max_threads = int(arg)
        elif opt in ('-v', '--verbose'):
            verbose = True
        else:
            print("unknown args")
            sys.exit(2)

    if target:
        targets_list.append(target)

    if listfile:
        with open(listfile, "r") as ins:
            for line in ins:
                addr = line.strip()

                if re.match(r'^#', addr):
                    continue
                if len(addr) == 0:
                    continue
                if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', addr):
                    targets_list.append(addr)

    if targets_list:
        threadLimiter = threading.BoundedSemaphore(max_threads)
        print("======== CVE-2019-0708 check start =======")
        results = start(targets_list, port, verbose)
        print("======== CVE-2019-0708 check complete =======")
        for ip in results:
            print("{} IS VULNERABLE!".format(ip))
        print("{} targets in total".format(len(targets_list)))
        if len(results):
            print("{} vulnerable host(s)".format(len(results)))
        else:
            print("No vulnerable host found")

    else:
        print("No targets")

if __name__ == "__main__":
    main(sys.argv)