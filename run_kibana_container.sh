#!/bin/bash

docker pull kibana
docker run -d --name kibana --link es:elasticsearch -p 5601:5601 kibana
