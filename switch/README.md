# OPP Software Switch

This is an implementation of the OPP Software Switch based on the [CPqD OpenFlow 1.3 softswitch][ofss13].

# Features in a nutshell

The OPP Switch is an OpenFlow 1.3 switch extended with support for:
* Stateful packet forwarding based on the [OpenState API][openstate]
* Packet generation based on the [InSP API][insp]

Such extensions to OpenFlow 1.3 are implemented using the *OpenFlow Experimenter* framework. The API to control them is defined in [oflib-exp/ofl-exp-beba.h](oflib-exp/ofl-exp-beba.h).

Moreover, OPP targets software accelleration. We improve the CPqD softswitch troughput while retaining the simplicity of the original CPqD code base.

# Getting Started

Similarly to the CPqD softswitch, the following components are available in this package:
* `ofdatapath`: the switch implementation
* `ofprotocol`: secure channel for connecting the switch to the controller
* `oflib`: a library for converting to/from 1.3 wire format
* `dpctl`: a tool for configuring the switch from the console

For more information on how to use these components please refer to the [original CPqD's documentation][ofss13]

## Building

Run the following commands in the `beba-switch` directory to build and install everything:

    $ ./boot.sh
    $ ./configure
    $ make
    $ sudo make install

## Running

Please refer to the [original CPqD's softswitch README][ofss13-readme]

## Pre-configured VM

A pre-configured VM with the environment already set up can be downloaded [here][pre-configured-vm].

# Contribute
Please submit your bug reports, fixes and suggestions as pull requests on
GitHub, or by contacting us directly.

# License
OPP Software Switch is released under the BSD license (BSD-like for
code from the original Stanford switch).

[beba]: http://www.beba-project.eu/
[openstate]: http://openstate-sdn.org/pub/openstate-ccr.pdf
[insp]: http://conferences.sigcomm.org/sosr/2016/papers/sosr_paper42.pdf
[ofss13]: http://cpqd.github.io/ofsoftswitch13/
[ofss13-readme]: https://github.com/CPqD/ofsoftswitch13/blob/master/README.md
[compileubuntu14]: http://tocai.dia.uniroma3.it/compunet-wiki/index.php/Installing_and_setting_up_OpenFlow_tools
[pre-configured-vm]: https://mega.nz/#!0Q9wTAyD!rUfJVawVm1U5B28UFAMRpIXIPYXqzfm8-yLbUkLSYKY
