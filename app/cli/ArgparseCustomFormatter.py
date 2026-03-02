#!/usr/bin/env python3

import argparse

class ArgparseCustomFormatter(
        # Preserve the description formatting
        argparse.RawDescriptionHelpFormatter,
        # Include the default value when running --help
        argparse.ArgumentDefaultsHelpFormatter
    ):
    pass