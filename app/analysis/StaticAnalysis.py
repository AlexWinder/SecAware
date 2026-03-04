#!/usr/bin/env python3

import json
import os
import subprocess
import xml.etree.ElementTree as XML

from app.utils.ConsoleColour import ConsoleColour

class StaticAnalysis:
    analysisFindings: list
    psalmConfigPath: str

    def __init__(self, filesForAnalysis):
        self.psalmConfigPath = "/tmp/psalm.xml"

        self.buildConfigurationFile()
        self.runAnalysis(filesForAnalysis)

    def buildConfigurationFile(self):
        if os.path.exists(self.psalmConfigPath):
            print(ConsoleColour.toYellow(f"Psalm configuration file already exists at {self.psalmConfigPath}. Skipping configuration file creation."))
            return

        psalmConfig = XML.Element('psalm')
        xmlTree = XML.ElementTree(psalmConfig)
        xmlTree.write(self.psalmConfigPath, encoding='utf-8', xml_declaration=True)

    def runAnalysis(self, targetDirectory):
        result = subprocess.run([
            "psalm",
            "--config", self.psalmConfigPath,
            "--taint-analysis",
            "--output-format=json",
            targetDirectory
        ], capture_output=True, text=True)

        self.analysisFindings = json.loads(result.stdout)