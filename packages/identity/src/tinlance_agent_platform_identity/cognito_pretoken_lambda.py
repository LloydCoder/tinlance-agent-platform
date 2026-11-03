"""AWS Lambda entrypoint for Cognito V2 tenant membership claims."""

from __future__ import annotations

import os
from collections.abc import Mapping
from functools import lru_cache

from .cognito_pretoken import CognitoPreTokenGenerationV2Handler, build_cognito_pretoken_handler


@lru_cache(maxsize=1)
def _configured_handler() -> CognitoPreTokenGenerationV2Handler:
    """Initialize and reuse the DynamoDB client across warm Lambda invocations."""

    import boto3
    from botocore.config import Config

    region = os.environ["AWS_REGION"]
    sdk_config = Config(
        connect_timeout=1,
        read_timeout=1,
        retries={"mode": "standard", "total_max_attempts": 2},
    )
    dynamodb = boto3.resource("dynamodb", region_name=region, config=sdk_config)
    return build_cognito_pretoken_handler(os.environ, dynamodb.meta.client)


_HANDLER = _configured_handler()


def lambda_handler(event: Mapping[str, object], context: object) -> dict[str, object]:
    """Cognito Pre Token Generation V2 Lambda handler."""

    del context
    return _HANDLER.handle(event)
