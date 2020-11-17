# XPlane-Wireshark-Dissector-C
## A Wireshark Dissector for Laminar Research's X-Plane Flight Simulator

#### How to build into Wireshark
The **packet.xplane.c** file can be added to your wireshark build to create either an inbuilt dissector or a plugin.
Refer to the wireshark/doc/README.dissector and README.plugins files that are part of [Wireshark's git repository.](https://gitlab.com/wireshark/wireshark).<br>

#### Just give me a plugin/dll to use:
Download the release that is appropriate for your version of Wireshark.<br>
To find your version goto Wireshark Menu -> Help -> About Wireshark -> Wireshark Tab and check the topmost line. Only the first 2 numbers (Major and Minor) are important. e.g. 3.4..... <br>
Copy the file into your wireshark/plugin/*version*/epan/ folder.<br>
Restart Wireshark if already running. <br>
You can check it is installed correctly in Wireshark Menu -> Help -> About Wireshark -> Plugins Tab. The Name will be xplane.dll with a type of dissector. <br>

I developed and tested this code on Win10 / MSVC 2019 x64.<br>
