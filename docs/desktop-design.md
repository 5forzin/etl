# Windows interface

[Figma sketch](https://www.figma.com/design/BQNC74KJoWRbj8JC0fIpOl?node-id=5-136).
The collapsed and expanded sketches are 360 pixels wide. They use editable
layers, auto layout, color variables and a shared input component. The client displays traffic
counters from its current session.

The main screen contains local proxy status, server, token and traffic. The power
icon connects or disconnects. Options reveals ports, backup, timeout and CA below
the main controls. The window measures its content and adjusts its height without
scrollbars. Wrapped errors also change the required height.

Opening and closing Options animates the native window height over 280 ms with
cubic ease-out. Fields fade in and the disclosure chevron rotates. Reversing the
animation starts from the current height. Width stays fixed and the renderer
resizes its DirectX target before drawing each frame. The window moves upward
only when growth would put its bottom below the monitor's work area.

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
