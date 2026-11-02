"""
Copyright start
Copyright (C) 2008 - 2026 FortinetInc.
All rights reserved.
FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
Copyright end
"""

from connectors.core.connector import Connector, ConnectorError, get_logger

from .operations import OPERATIONS, check_health_ex

logger = get_logger('fortinet-fortiedrv2')


class FortiEDR(Connector):

    def execute(self, config, operation, params, **kwargs):
        handler = OPERATIONS.get(operation)
        if not handler:
            raise ConnectorError('Unknown operation: {0}'.format(operation))
        try:
            logger.info('Executing operation: {0}'.format(operation))
            return handler(config, params)
        except ConnectorError:
            raise
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(str(err))

    def check_health(self, config):
        try:
            return check_health_ex(config)
        except Exception as err:
            logger.exception(err)
            raise ConnectorError(str(err))
