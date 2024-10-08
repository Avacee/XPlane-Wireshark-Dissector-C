# XPlane-Wireshark-Dissector-C
## A Wireshark Dissector for Laminar Research's X-Plane Flight Simulator.

### How to build this dissector into your own Wireshark.

To build Wireshark refer to these resources:
* Windows: https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
* Linux: https://gist.github.com/syneart/2d30c075c140624b1e150c8ea318a978  

There are 2 options for integrating an X-Plane dissector into Wireshark:
* As a plugin (quickest recompile during development)
  * Copy <code>packet-xplane.c</code> and <code>CMakeLists.txt</code> into <code>wireshark\private_plugins\xplane</code>
  * Copy <code>wireshark\CMakeListsCustom.txt.example</code> to <code>wireshark\CMakeListsCustom.txt</code>
  * Edit <code>wireshark\CMakeListsCustom.txt</code> and change <code>private_plugins/foo</code> to <code>private_plugins/xplane</code> and uncomment the line
  * Rerun from the cmake step.

* Within the main libwireshark.dll dissector library
  * Copy <code>packet-xplane.c</code> into <code>wireshark\epan\dissectors</code>
  * Copy <code>wireshark\epan\dissectors\CMakeListsCustom.txt.example</code> to <code>wireshark\epan\dissectors\CMakeListsCustom.txt</code>
  * Edit <code>wireshark\epan\dissectors\CMakeListsCustom.txt</code> and change <code>packet-foo.c</code> to <code>packet-xplane.c</code> and uncomment the line.
  * Rerun from the cmake step.

For more information on writing wireshark dissectors refer to the wireshark\doc\README.subject files.

### Just give me a .dll/.so to use.
Download the release that is appropriate for your version of Wireshark.  
To find your version goto _Menu->Help->About Wireshark->Wireshark_ and check the topmost line. Only the first 2 numbers (Major and Minor) are important. e.g. 3.4.  
Copy the plugin into one of the following folders:
  * Wireshark's _Personal_Plugins_Folder_\epan\
  * Wireshark's _Global_Plugins_Folder_\epan\ 
  * Your wireshark\plugins\ _version_ \epan\ folder.

I recommend the Personal_Plugins_Folder as this is not cleared by wireshark updates.  
The folders can be found via _Menu -> Help -> About Wireshark -> Folders -> Personal Plugins_

Restart Wireshark if already running.   
You can check Wireshark has loaded the plugin via Menu->Help->About Wireshark->Plugins Tab. The name will be *xplane* with a type of *dissector*.  

Developed and tested on Windows 10+11 and Microsoft Visual Studio 2019/2022  
Linux testing on Ubuntu 20.04.1 and WSL2 (Ubuntu and Debian)

### Usage.
The proto declaration is "xplane" and the protofields have been added using the format xplane.$header$.$element$".  
So to view only BECN packets the display filter will be "xplane.becn"  
Conversely to see all packet except BECN (as there are so many) filter on "xplane && !xplane.becn"  
To only see those DATA packets with an index of 0 (Frame Rate Info) filter on "xplane.data.index == 0"  

###### TODO:
