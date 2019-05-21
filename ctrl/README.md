# OPP Controller

This is an implementation of the OPP Controller based on the [RYU OpenFlow Controller][ryu]. 

## Running

To install the OPP Controller on your machine:

      python ./setup.py install

Once installed, the OPP Controller can be executed using the `ryu-manager` command. Please refer to the [original RYU documentation][ryu] on how to use this controller.

## OPP Extensions & App Samples

Most of the OPP extensions (implemented as *OpenFlow Experimenter Extensions*) are implemented in [ryu/ofproto/beba_v1_0_parser.py](ryu/ofproto/beba_v1_0_parser.py).

OPP app samples can be found inside [ryu/app/beba](ryu/app/beba)

# Contribute
Please submit your bug reports, fixes and suggestions as pull requests on
GitHub, or by contacting us directly.

# License
OPP Controller is released under the Apache 2.0 License.

[beba]: http://www.beba-project.eu/
[ryu]: http://osrg.github.io/ryu
