# Windows interface

[Figma sketch](https://www.figma.com/design/BQNC74KJoWRbj8JC0fIpOl?node-id=5-136).
The Proxy and Options screens are 360 × 400. They use editable layers, auto
layout, color variables and a shared input component. The client displays traffic
counters from its current session.

The main screen contains local proxy status, server, token and traffic. The power
icon connects or disconnects. Ports, backup, timeout and CA have a separate Options
screen so opening settings keeps the window compact. Both screens fit without
scrolling at the default size; longer errors can scroll within the content area.

The native window has no caption or border. Drag the header to move it; custom
controls minimize or close it. Windows 11 supplies rounded corners when supported.
Closing the window keeps the
proxy in the tray; Exit closes its connections. “Proxy active” means the local
listener is open. The remote connection is verified when an application uses it.

The renderer uses Dear ImGui and DirectX 11. Inter ships inside the executable
under SIL OFL. Colors: background `#141716`, inputs `#1e2220`, border `#343b37`,
text `#eef1ef`, secondary text `#a1aaa4` and action `#b8ecd0`. State transitions
use exponential interpolation with a 180 ms time constant. The renderer pauses
while the window is hidden or minimized.

ImGui does not provide the same accessibility integration as Win32 controls.
Keyboard navigation is enabled; screen reader support remains a limitation.
