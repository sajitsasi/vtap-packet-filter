# vtap-packet-filter

This repository contains a sample program written in C to interpret packets
from Azure V-TAP by removing the VxLAN header and printing packet details

## Requirements

1. VTAP is still in private preview and instructions on how to enroll in the preview can be found [here](https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-tap-overview). Without being enrolled, you will not be able to use VTAP
2. VTAP can be configured only from Azure CLI versions >= 2.0.46
3. Enable VTAP extension to Azure CLI by running ```az extension add -n virtual-network-tap```

## Installation

1. Create a Resource Group, with a single VNET
2. Create two subnets - ```subnet0``` and ```subnet1```
3. Create 2 VMs (Ubuntu 18.04) - we'll call them ```MonitoredVM1``` and ```MonitoredVM2``` in ```subnet0``` and ```subnet1``` respectively
4. Create another VM (OS: Ubuntu 18.04) - we'll call it ```CollectorVM``` in ```subnet0```
5. Go [here](https://docs.microsoft.com/en-us/azure/virtual-network/tutorial-tap-virtual-network-cli) and follow steps outlined.  Note that the destination for the virtual network TAP is going to be the network interface on the ```CollectorVM```
6. Login to the collector VM and run the following commands:
   * ```sudo apt-get update```
   * ```sudo apt-get upgrade -y```
   * ```sudo apt-get install build-essential libpcap-dev -y```
   * ```cd; git clone https://github.com/sajitsasi/vtap-packet-filter.git```
   * ```cd vtap-packet-filter/src/packetfilter```
   * ```make```
7. Now you're ready to start capturing.  To do so, run ```sudo ~/vtap-packet-filter/src/packetfilter/vtap-pf -i eth0``` and you should start seeing the de-encapsulated packets from the two VMs

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
