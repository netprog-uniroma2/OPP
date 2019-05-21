# DDoS use case

Once set the OPP environment, open two terminals.

In the first start the controller for 1 or 2 state copies by typing

    ryu-manager ddos_use_case_opp_X.py

Then in the second shell type

    sudo python ddos_topology.py

to start Mininet with the DDoS use case topology.

To originate the traffic from ASs to servers it is sufficient to execute the script containing *hping3* commands, within the Mininet CLI:

    mininet> source hping3n

To see the evolution of states in the switches use the dpctl tool as follows:

    sudo dpctl unix:/tmp/swX stats-state -c

where the X has to be substituted by the id of the desired switch (from 1 to 8).
