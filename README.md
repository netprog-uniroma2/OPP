# Open Packet Processor (OPP)

This repostitory contains the implementation for the OPP software switch and controller.

Our goal is to devise a data plane abstraction and prototype implementations for future-proof network devices capable to be repurposed with middlebox-type functions well beyond static packet forwarding, with a focus on stateful processing and packet generation.

## Repository structure

The repository is organized as follows:

- [*opp/switch*](switch) contains the implementation of the user-space software switch;
- [*opp/ctrl*](ctrl) contains the implementation of the controller compatible to the software switch;
- Use cases, applications and examples exploiting the OPP functionalities can be found in the [*opp/ctrl/ryu/app/beba/*](ctrl/ryu/app/beba) folder.
