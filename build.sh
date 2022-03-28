#!/bin/bash

# cleanup
rm -rf deploy_me.zip package

# install dependencies
pip3 install --target ./package -r requirements.txt

# build zip with all data
cd package
zip -r ../deploy_me.zip .
cd ..
zip -g deploy_me.zip lambda_function.py
