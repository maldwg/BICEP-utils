from abc import ABC, abstractmethod
from datetime import datetime

class IDSParser(ABC):

    @property
    @abstractmethod
    async def alertFileLocation(self):
        pass
    @abstractmethod
    async def parse_alerts_from_file(self):
        pass
    @abstractmethod
    async def parse_alerts_from_network_traffic(self):
        pass

class Alert():
    """
    Class which contains the most important fields of an alert (one line of anomaly).
    It presents a standardized interface for the different IDS to map their distinct alerts to.
    """
    time: datetime
    source: str
    destination: str
    severity: int
    type: str
    message: str




class IDSBase(ABC):
    """
    Abstract base class for all IDS supported by BICEP
    Each IDS involved needs to inherit from this base class and implement the following methods and attributes
    """
    container_id: int = None
    ensemble_id: int = None
    
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


    async def stopAnalysis(self):
        from src.utils.fastapi.utils import stop_process, tell_core_analysis_has_finished

        await stop_process(self.pid)
        self.pid = None
        await tell_core_analysis_has_finished(self)

        
    # def sendMetrics(self):
    #     pass

    
    # def sendAlerts(self):
    #     pass
