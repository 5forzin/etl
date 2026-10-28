# Windows interface

The desktop is a compact, 400-pixel-wide window. Its monochrome palette uses
near-black backgrounds, graphite surfaces, subtle outlines and a white primary
action. Inter, consistent line icons and generous spacing define the hierarchy.

The connection screen shows status, the configured server, a two-position mode
selector, the primary action, Open browser and Settings. Server credentials and
advanced fields live on a separate Settings screen. Traffic counters appear only
while the connection is active and use actual session data.

- **Proxy only** opens the configured local SOCKS5/HTTP listener. Applications
  must opt into that proxy. “Proxy active” means the local listener is open;
  remote authentication happens when an application uses it.
- **Full mode** routes the PC through the existing TUN engine. A separate worker
  requests administrator permission; the desktop and browser remain unelevated.
  The interface reflects connecting, connected, disconnecting and failure states.
  Cancel and Disconnect request cleanup before the worker exits. The existing
  health checks and restoration guard remain active.

The mode selection slides with exponential easing. Hover and focus transitions
use a 90 ms time constant; page content fades over 100 ms. Native window height
changes use a 280 ms cubic ease-out. Reversing an animation starts at its current
position. Windows' reduced-animation preference disables these transitions.
Keyboard navigation has visible focus outlines.

The menu surface uses a 20-pixel radius and a fine inner outline. The primary
button has a pill shape. Inputs use a 10-pixel radius and persistent labels.
Colors: background `#111111`, surface `#181818`, selected surface `#2b2b2b`,
border `#363636`, text/action `#f1f1f1`, secondary text `#9c9c9c`.

Open browser starts or reuses a proxy on the configured port, then opens Edge or
Chrome with its own ETL profile. It does not change the user's normal browser
profile or system proxy. Choosing Open browser while disconnected starts Proxy
only; Full mode requires its explicit primary action.

An available update expands inline below the main controls. Later dismisses it;
Update downloads and verifies it before disconnecting and restarting the client.
Settings contains the current version and a manual update check.

The window has a draggable header, custom minimize/close controls and native
rounded corners on supported Windows versions. Closing hides it in the tray;
Exit disconnects before quitting. Errors expand the content instead of covering
actions. DirectX targets resize before each frame. The window moves upward when
necessary to remain inside the monitor's work area.

Dear ImGui and DirectX 11 render the interface; Inter is embedded under SIL OFL.
Rendering pauses while hidden or minimized. ImGui keyboard navigation is enabled,
but screen reader integration remains limited.
