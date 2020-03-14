# Controller to start all other processes/jobs
# Using the python multiprocessing package

import multiprocessing
from time import sleep
import daemon

def process1(queue):
    sleep(1)
    queue.put("node1")
    queue.put("node2")
    print(queue.get())
    print("aaa")

def process2(queue):
    sleep(1)
    print(queue.get())
    print("bbb")

def controller():
    queue = multiprocessing.Queue()
    p1 = multiprocessing.Process(target=process1, args=(queue,))
    #p1.daemon = True
    p2 = multiprocessing.Process(target=process2, args=(queue,))
    #p2.daemon = True
    p1.start()
    p2.start()


if __name__ == "__main__":
    controllerprocess = multiprocessing.Process(target=controller)
    controllerprocess.start()