# Load-driven Forwarding

### Requirements:
	iperf3	
### Description
	
The code below implements a load-driven forwarding application based on flowlets in the Beba switch environment.

![alt tag](https://raw.githubusercontent.com/angelotulumello/beba-ctrl/beba_advanced/ryu/app/beba/load_driven_forwarding/ldf-topo.png)

The topology is composed of three leaves and two spines in which all leaves are connected to both spines, so having two possible paths to reach the same destination. 
It is possible to change the RTT in the topology described in leafSpineTopo.py by changing the delays, as well as the constant RTT defined in the controller code in *ldf-flowlets.py*. To evaluate the probe mechanism (MPLS packets) and the forwarding behaviour of the flowlets, start some flows and a tcpdump capture on the interfaces between leaves and spines. For this purpose, the iperf3 tool was used to make tests, and it is required for the application to work properly.

### Setup *improved-ldf-flowlets.py*:

To start the application open two ssh terminals (with the -X option).
In the first shell type:
	
	ryu-manager improved-ldf-flowlets.py

to start the controller.

In the second shell type: 

	sudo python leafSpineTopo.py 

to start the topology.

In the mininet CLI start a new flow by typing

    h3 iperf3 -c h2 -p 6667 -M 1400 -l 10k -b 1m -t 60 &

that is a TCP flow limited to 1 Mbps from h3 to h2, for an overall time of 60 seconds.
A figure will span showing a plot in which in real time are represented the flows' chosen paths, highlighting the 
*flowlet* division mechanism.

Now start another flow from h1 to h2 by typing

    h1 iperf3 -c h2 -p 6666 -M 1400 -l 10k -b 4m -t 20

In the plot it can be seen that the two flows are balanced between the two available paths to h2.