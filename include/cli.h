#ifndef PKTX_CLI_H
#define PKTX_CLI_H

#include <stdbool.h>
#include "strm.h"

// Run interactive wizard mode
void cli_run_interactive(void);

// Process command line arguments
int cli_run_args(int argc, char *argv[]);

#endif // PKTX_CLI_H
