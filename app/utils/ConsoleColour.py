#!/usr/bin/env python3

class ConsoleColour:
    def toGreen(text):
        return f"\033[92m{text}\033[0m"

    def toRed(text):
        return f"\033[91m{text}\033[0m"

    def toBlue(text):
        return f"\033[94m{text}\033[0m"
    
    def toYellow(text):
        return f"\033[93m{text}\033[0m"
        