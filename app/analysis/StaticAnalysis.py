#!/usr/bin/env python3

import json
import os
import subprocess
import xml.etree.ElementTree as XML

from app.utils.ConsoleColour import ConsoleColour

class StaticAnalysis:
    analysisFindings: list
    analysisExecuted: bool
    psalmConfigPath: str

    def __init__(self, filesForAnalysis, logger):
        self.analysisExecuted = False
        self.analysisFindings = []
        self.logger = logger
        self.psalmConfigPath = "/tmp/psalm.xml"

        self.buildConfigurationFile()
        try:
            self.runAnalysis(filesForAnalysis)
        except Exception:
            self.logger.error(f"Error occurred while running static analysis.")

    def buildConfigurationFile(self):
        self.logger.info(f"Building Psalm configuration file at {self.psalmConfigPath}.")

        if os.path.exists(self.psalmConfigPath):
            self.logger.info(ConsoleColour.toYellow(f"Psalm configuration file already exists at {self.psalmConfigPath}. Skipping configuration file creation."))
            return

        psalmConfig = XML.Element('psalm')
        xmlTree = XML.ElementTree(psalmConfig)
        xmlTree.write(self.psalmConfigPath, encoding='utf-8', xml_declaration=True)

        self.logger.info(f"Successfully created Psalm configuration file at {self.psalmConfigPath}.")
        self.logger.debug(XML.tostring(psalmConfig))

    def runAnalysis(self, targetDirectory):
        self.logger.info(f"Running static analysis with Psalm on target directory: {targetDirectory}.")

        result = subprocess.run([
            "psalm",
            "--config", self.psalmConfigPath,
            "--taint-analysis",
            "--output-format=json",
            targetDirectory
        ], capture_output=True, text=True)

        self.analysisFindings = json.loads(result.stdout)
        self.analysisExecuted = True

        self.logger.info(f"Completed static analysis with Psalm. Found {len(self.analysisFindings)} issues.")
        self.logger.debug(self.analysisFindings)