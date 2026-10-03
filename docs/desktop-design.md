# Windows interface

[Figma sketch](https://www.figma.com/design/BQNC74KJoWRbj8JC0fIpOl?node-id=5-136).
The Proxy and Settings screens use editable layers, auto layout, color variables
and a button from Simple Design System. Traffic figures in the sketch are sample
values; the client displays counters from its current session.

The main screen contains local proxy status, server, token and connection action.
Ports, backup, timeout and CA live under Options. Closing the window keeps the
proxy in the tray; Exit closes its connections. “Proxy active” means the local
listener is open. The remote connection is verified when an application uses it.

The renderer uses Dear ImGui and DirectX 11. Inter ships inside the executable
under SIL OFL. Colors: background `#141716`, inputs `#1e2220`, border `#343b37`,
text `#eef1ef`, secondary text `#a1aaa4` and action `#b8ecd0`. State transitions
use exponential interpolation with a 180 ms time constant. The renderer pauses
while the window is hidden or minimized.

ImGui does not provide the same accessibility integration as Win32 controls.
Keyboard navigation is enabled; screen reader support remains a limitation.
