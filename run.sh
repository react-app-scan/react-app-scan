#!/bin/bash
python3 ./main.py ./motivating-example/react -t xss --timeout 120 --run-env ./jsx-test/tmp_env/0 --log-base-location ./jsx-test/logs/0 --babel ./motivating-example/react --export all --is-jsx-application --service-entry ./motivating-example/API/index.js
