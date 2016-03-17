#!/bin/bash

docker pull kibana
docker run kibana --link es:elasticsearch -p 5601:5601 kibana
