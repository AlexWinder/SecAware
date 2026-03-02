#!/usr/bin/env python3

class ConsoleColour:
    def toRed(text):
        return f"\033[91m{text}\033[0m"

    def toGreen(text):
        return f"\033[92m{text}\033[0m"
    
    def toYellow(text):
        return f"\033[93m{text}\033[0m"