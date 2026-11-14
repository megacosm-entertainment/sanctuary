package realm

import "sanctuary/internal/echo"

// StubHandler is the stage-02 stub realm: the echo handler, reached through
// the realm protocol. The gateway's in-process stub and the sanctuary-realm
// binary both serve it, so they look the same to a player.
var StubHandler = echo.Handler{
	Banner: "Sanctuary stub realm, stage 02: reached through the realm protocol.\n" +
		"Type anything and it comes back. 'help' lists commands; '>lobby' takes you back to the lobby.\n",
	Shutdown: "\nThe realm is shutting down. Goodbye.\n",
}
