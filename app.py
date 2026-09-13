#!/usr/bin/env python3
import os

import aws_cdk as cdk

from phossil.phossil_stack import PhossilStack

app = cdk.App()

PhossilStack(
    app,
    "phossil",
    stack_name="phossil",
    env=cdk.Environment(
        account=os.environ.get("CDK_DEFAULT_ACCOUNT"),
        region=app.node.try_get_context("region") or "us-east-1",
    ),
)

app.synth()
