from abc import ABC, abstractmethod

class IDSBase(ABC):
    """
    Abstract base class for all IDS supported by BICEP
    Each IDS involved needs to inherit from this base class and implement the following methods nad attributes
    """
    
    @property
    @abstractmethod
    def log_location(self):
        pass

    @property
    @abstractmethod
    def network_interface(self):
        pass

    @property
    @abstractmethod
    def configuration_location(self):
        pass

    @property
    @abstractmethod
    def container_id(self):
        pass

    @abstractmethod
    def configure(self, file_path):
        """
        Method for setting up the main configuration file in the corresponding location
        gets a file content as input and needs to save it to the location necesary for the IDS system
        """
        return "base implementation"

    @abstractmethod
    def configure_ruleset(self, file_path):
        """
        Method for setting up the main configuration file in the corresponding location
        gets a file content as input and needs to save it to the location necesary for the IDS system
        """
        return "base implementation"


    @abstractmethod
    def startStaticAnalysis(self, file_path: str, container_id: int):
        """
        Method to trigger a static analysis. This method takes a file as input and executes certain OS commands to trigger the analysis
        """
        pass

        
    @abstractmethod
    def startNetworkAnalysis(self):
        """
        Method to start the network analysis mode where the traffic is caputred on an internal network interface
        """
        pass


        
    @abstractmethod
    def stopAnalysis(self):
        """
        Stop ongoing analysis' by interrputing the process
        """
        pass

        
    # def sendMetrics(self):
    #     pass

    
    # def sendAlerts(self):
    #     pass

        
    # @abstractmethod
    # def configure(self):
    #     pass