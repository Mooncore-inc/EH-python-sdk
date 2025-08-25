"""
System operations for Event Horizon SDK
"""

import aiohttp
from typing import Dict, Any, Optional
from exceptions import NetworkError
from models import SystemInfo, StatsOverview


class SystemManager:
    """Manages system operations and monitoring"""
    
    def __init__(self, config):
        """
        Initialize system manager
        
        :param config: Client configuration
        """
        self.config = config
    
    async def get_system_health(self) -> SystemInfo:
        """
        Get system health status
        
        :return: SystemInfo object
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.config.api_base_url}/system/health",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return SystemInfo.from_dict(data)
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to get system health: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting system health: {str(e)}")
    
    async def get_system_info(self) -> Dict[str, Any]:
        """
        Get system information
        
        :return: System information dictionary
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.config.api_base_url}/system/info",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to get system info: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting system info: {str(e)}")
    
    async def get_stats_overview(self) -> StatsOverview:
        """
        Get system statistics overview
        
        :return: StatsOverview object
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.config.api_base_url}/stats/overview",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return StatsOverview.from_dict(data)
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to get stats overview: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting stats overview: {str(e)}")
    
    async def get_user_activity_stats(self) -> Dict[str, Any]:
        """
        Get user activity statistics
        
        :return: User activity statistics
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.config.api_base_url}/stats/users/activity",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to get user activity stats: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting user activity stats: {str(e)}")
    
    async def get_message_trends(self) -> Dict[str, Any]:
        """
        Get message trends statistics
        
        :return: Message trends statistics
        """
        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(
                    f"{self.config.api_base_url}/stats/messages/trends",
                    timeout=aiohttp.ClientTimeout(total=self.config.timeout)
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        error_data = await response.json()
                        raise NetworkError(
                            f"Failed to get message trends: {error_data.get('message', 'Unknown error')}",
                            error_code=str(response.status)
                        )
            except aiohttp.ClientError as e:
                raise NetworkError(f"Network error getting message trends: {str(e)}")
    
    async def ping_server(self) -> float:
        """
        Ping server to measure latency
        
        :return: Response time in milliseconds
        """
        import time
        
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.config.api_base_url}/system/health",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status == 200:
                        end_time = time.time()
                        return (end_time - start_time) * 1000  # Convert to milliseconds
                    else:
                        return -1  # Error
        except Exception:
            return -1  # Error
    
    async def check_server_status(self) -> Dict[str, Any]:
        """
        Comprehensive server status check
        
        :return: Server status information
        """
        status = {
            "timestamp": None,
            "health": None,
            "ping": None,
            "stats": None,
            "overall_status": "unknown"
        }
        
        try:
            # Check system health
            health_info = await self.get_system_health()
            status["health"] = health_info
            status["timestamp"] = health_info.timestamp
            
            # Check ping
            ping_time = await self.ping_server()
            status["ping"] = ping_time
            
            # Get basic stats
            try:
                stats = await self.get_stats_overview()
                status["stats"] = stats
            except Exception:
                status["stats"] = None
            
            # Determine overall status
            if (status["health"] and 
                status["health"].status == "healthy" and 
                status["ping"] > 0):
                status["overall_status"] = "healthy"
            elif status["health"] and status["health"].status == "healthy":
                status["overall_status"] = "degraded"
            else:
                status["overall_status"] = "unhealthy"
                
        except Exception as e:
            status["overall_status"] = "error"
            status["error"] = str(e)
        
        return status
