from abc import ABC, abstractmethod
from ..general_utilities import stop_process, ANALYSIS_MODES
import json 
class IDSParser(ABC):

    timestamp_format = '%Y-%m-%dT%H:%M:%S.%f%z'

    @property
    @abstractmethod
    async def alert_file_location(self):
        pass
    @abstractmethod
    async def parse_alerts(self, analysis_mode: ANALYSIS_MODES ,file_location):
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
    # TODO 0: refactor alerts so that there is a destination port and source port differentioation
    """
    Class which contains the most important fields of an alert (one line of anomaly).
    It presents a standardized interface for the different IDS to map their distinct alerts to.
    """
    time: str
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    severity: float
    type: str
    message: str

    def __init__(self, time=None, source_ip=None, source_port=None, destination_ip=None, destination_port=None, severity=None, type=None, message=None):
        self.time=time
        self.source_ip=source_ip
        self.source_port=source_port
        self.destination_ip=destination_ip
        self.destination_port=destination_port
        self.severity=severity
        self.type=type
        self.message=message

    @classmethod
    def from_json(cls, json_alert: str):
        # replace none with null to be able to load from json
        json_str = json_alert.replace('None', 'null')
        # replace single quotes with double quotes to be able to load it from json
        json_str = json_str.replace("'",'"')
        alert_dict = json.loads(json_str)
        return Alert(
            time=alert_dict["time"],
            source_ip=alert_dict["source_ip"],
            source_port=alert_dict["source_port"],
            destination_ip=alert_dict["destination_ip"],
            destination_port=alert_dict["destination_port"],
            severity=alert_dict["severity"],
            type=alert_dict["type"],
            message=alert_dict["message"]
        )

    def __str__(self):
        return f"{self.time}, From: {self.source_ip}:{self.source_port}, To: {self.destination_ip}:{self.destination_port}, Type: {self.type}, Content: {self.message}, Severity: {self.severity}"

    def to_dict(self):
        return {
            "time": self.time,  
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
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
    pids: list[int] = []
    # Id of the dataset used to trigger a static analysis
    dataset_id: int = None
    static_analysis_running: bool = False
    send_alerts_periodically_task = None
    tap_interface_name: str = None
    
    @property
    @abstractmethod
    async def log_location(self):
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

    async def stop_all_processes(self):
        remove_process_ids = []
        if self.pids != []:
            for pid in self.pids:
                await stop_process(pid)
                remove_process_ids.append(pid)
        for removed_pid in remove_process_ids:
            self.pids.remove(removed_pid)