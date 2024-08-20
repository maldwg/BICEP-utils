from abc import ABC, abstractmethod
from datetime import datetime

class IDSParser(ABC):

    timestamp_format = '%Y-%m-%dT%H:%M:%S.%f%z'

    @property
    @abstractmethod
    async def alert_file_location(self):
        pass
    @abstractmethod
    async def parse_alerts(self, file_location):
        """
        Method triggered once after the static analysis is complete or periodically for a network analysis. 
        Takes in the whole file, reads it, parses it, deletes it and returns the parsed lines
        """
        pass

    @abstractmethod
    async def parse_line(self, line):
        """
        Method to parse one line at a time into the Alert object
        """
        pass

    @abstractmethod
    async def normalize_threat_levels(self, threat: int):
        """
       Normalize the threat levels which are individual for each IDS from 0 to 1 (1 being the highest)
       returns decimal values with only 2 decimals
        """
        pass

class Alert():
    """
    Class which contains the most important fields of an alert (one line of anomaly).
    It presents a standardized interface for the different IDS to map their distinct alerts to.
    """
    time: str
    source: str
    destination: str
    severity: float
    type: str
    message: str

    def __init__(self, time=None, source=None, destination=None, severity=None, type=None, message=None):
        self.time=time
        self.source=source
        self.destination=destination
        self.severity=severity
        self.type=type
        self.message=message

    def __str__(self):
        return f"{self.time}, From: {self.source}, To: {self.destination}, Type: {self.type}, Content: {self.message}, Severity: {self.severity}"

    def to_dict(self):
        return {
            # Convert datetime to ISO format string to be JSON serializable
            "time": self.time,  
            "source": self.source,
            "destination": self.destination,
            "severity": self.severity,
            "type": self.type,
            "message": self.message
        }

class IDSBase(ABC):
    """
    Abstract base class for all IDS supported by BICEP
    Each IDS involved needs to inherit from this base class and implement the following methods and attributes
    """
    container_id: int = None
    ensemble_id: int = None
    pid: int = None
    # Id of the dataset used to trigger a static analysis
    dataset_id: int = None
    static_analysis_running: bool = False
    send_alerts_periodically_task = None
    
    @property
    @abstractmethod
    async def log_location(self):
        pass

    @property
    @abstractmethod
    async def network_interface(self):
        pass

    @property
    @abstractmethod
    async def configuration_location(self):
        pass

    @abstractmethod
    async def configure(self, file_path):
        """
        Method for setting up the main configuration file in the corresponding location
        gets a file content as input and needs to save it to the location necesary for the IDS system
        """
        return "base implementation"

    @abstractmethod
    async def configure_ruleset(self, file_path):
        """
        Method for setting up the main configuration file in the corresponding location
        gets a file content as input and needs to save it to the location necesary for the IDS system
        """
        return "base implementation"


    @abstractmethod
    async def startStaticAnalysis(self, file_path: str, container_id: int):
        """
        Method to trigger a static analysis. This method takes a file as input and executes certain OS commands to trigger the analysis
        """
        pass

        
    @abstractmethod
    async def startNetworkAnalysis(self):
        """
        Method to start the network analysis mode where the traffic is caputred on an internal network interface
        """
        pass

    @abstractmethod
    async def stopAnalysis(self):
        """
        Method for stopping the process used to trigger the analysis. Can be overwritten in the calss implementation for the IDS
        """
        # Example implementation:

        # await stop_process(self.pid)
        # self.pid = None
        # await tell_core_analysis_has_finished(self)

        
    # def sendMetrics(self):
    #     pass

    
    # def sendAlerts(self):
    #     pass
