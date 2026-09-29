#ifndef STATUS_H
#define STATUS_H

/* the status bar state SpringBoard's senkostatus hook reads */
void status_set(int enabled);

/* enabled, with the physical interface the tunnel rides: "1 en0". springboard
   takes the wifi glyph away whenever configd's primary interface is not wifi,
   and the tunnel is primary while it carries the system dns, so the hook needs
   to know the tunnel itself still leaves by wifi */
void status_set_on(const char *physical_ifname);

#endif
