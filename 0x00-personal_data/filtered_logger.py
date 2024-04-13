#!/usr/bin/env python3
"""
This module provides a class and a function for filtering sensitive data in
log messages.
"""

import re
import logging
import os
import mysql.connector
from typing import List

PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """ Constructor method
        """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Formats the log message
        """
        message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, message,
                            self.SEPARATOR)


def get_logger() -> logging.Logger:
    """ Returns a logging object
    """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """
    Returns the log message obfuscated.

    Args:
        fields (List[str]): A list of field names to be redacted.
        redaction (str): The string to replace the sensitive data with.
        message (str): The log message to be filtered.
        separator (str): The separator used to separate field-value pairs.

    Returns:
        str: The filtered log message with sensitive data redacted.
    """
    for field in fields:
        message = re.sub(field + "=.*?" + separator,
                         field + "=" + redaction + separator, message)
    return message


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Returns a MySQL connector object
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME') or 'root'
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD') or ''
    host = os.getenv('PERSONAL_DATA_DB_HOST') or 'localhost'
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    db_connections = mysql.connector.connect(
        user=user,
        password=passwd,
        host=host,
        database=db_name
    )
    return db_connections
