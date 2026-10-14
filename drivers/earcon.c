#include "speaker.h"

// The NAS has no audio hardware driver: earcons are silent no-ops. The
// HDA / SB16 / PC-speaker drivers live in yesos-lab.
U0 speaker_event(BeepEvent event) {
    (void)event;
}
