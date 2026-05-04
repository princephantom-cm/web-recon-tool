# utils/logger.py

import logging
import os
from datetime import datetime
from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme


# Custom theme
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "critical": "bold red blink"
})

console = Console(theme=custom_theme)


def setup_logger(name: str = "web-recon", log_file: bool = True, level: str = "INFO") -> logging.Logger:
    """
    Logger setup karta hai — console (rich) + file dono mein log karta hai.
    
    Args:
        name: Logger name
        log_file: File mein bhi save kare ya nahi
        level: Log level (DEBUG, INFO, WARNING, ERROR)
    
    Returns:
        Configured logger
    """
    
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    # Agar handlers already hain toh dobara add mat karo
    if logger.handlers:
        return logger
    
    # Rich console handler
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        rich_tracebacks=True,
        markup=True
    )
    rich_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.addHandler(rich_handler)
    
    # File handler
    if log_file:
        log_dir = "logs"
        os.makedirs(log_dir, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_filename = os.path.join(log_dir, f"recon_{timestamp}.log")
        
        file_handler = logging.FileHandler(log_filename, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str = "web-recon") -> logging.Logger:
    """Existing logger return karta hai ya naya banata hai."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        return setup_logger(name)
    return logger


# Shortcut functions
def log_info(msg: str):
    get_logger().info(msg)

def log_success(msg: str):
    get_logger().info(f"[success]✅ {msg}[/success]")

def log_warning(msg: str):
    get_logger().warning(f"[warning]⚠️  {msg}[/warning]")

def log_error(msg: str):
    get_logger().error(f"[error]❌ {msg}[/error]")

def log_critical(msg: str):
    get_logger().critical(f"[critical]🔴 {msg}[/critical]")