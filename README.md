# XPlane-Wireshark-Dissector-C
## A Wireshark Dissector for Laminar Research's X-Plane Flight Simulator

#### How to add this dissector into Wireshark

To build Wireshark refer to these resources:
* Windows: https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html
* Linux: https://gist.github.com/syneart/2d30c075c140624b1e150c8ea318a978  

There are 2 options for integrating an X-Plane dissector into Wireshark:
* As a plugin (quickest recompile during development)
  * Copy <code>packet-xplane.c</code> and <code>CMakeLists.txt</code> into <code>wireshark\plugins\epan\xplane</code>
  * Copy <code>wireshark\CMakeListsCustom.txt.example</code> to <code>wireshark\CMakeListsCustom.txt</code>
  * Edit <code>wireshark\CMakeListsCustom.txt</code> and change <code>plugins/epan/foo</code> to <code>plugins/epan/xplane</code> and uncomment the line
  * Rerun from the cmake step.

* Within the main libwireshark.dll dissector library
  * Copy <code>packet-xplane.c</code> into <code>wireshark\epan\dissectors</code>
  * Copy <code>wireshark\epan\dissectors\CMakeListsCustom.txt.example</code> to <code>wireshark\epan\dissectors\CMakeListsCustom.txt</code>
  * Edit <code>wireshark\epan\dissectors\CMakeListsCustom.txt</code> and change <code>packet-foo.c</code> to <code>packet-xplane.c</code> and uncomment the line.
  * Rerun from the cmake step.

For more information on writing wireshark dissectors refer to the wireshark\doc\README.subject files.

### Just give me a .dll/.so to use:
Download the release that is appropriate for your version of Wireshark.  
To find your version goto Menu->Help->About Wireshark->Wireshark Tab and check the topmost line. Only the first 2 numbers (Major and Minor) are important. e.g. 3.4.  
Copy the plugin into your wireshark/plugin/*version*/epan/ folder.  
Restart Wireshark if already running.   
You can check wireshark has loaded the plugin via Menu->Help->About Wireshark->Plugins Tab. The name will be *xplane* with a type of *dissector*.  

Developed and tested on Windows 10 and Microsoft Visual Studio 2019.  
Linux development and testing on Ubuntu 20.04.1 and Debian 10.6.

###### TODO:
[ ] Use wireshark's expert mechanism instead of validate_packet() just returning 0.  
[ ] Add descriptive lookups for DATA packets and use wmem_file_scope().
