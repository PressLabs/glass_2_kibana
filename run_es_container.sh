#!/bin/bash

docker pull elasticsearch
docker run -e ES_HEAP_SIZE=16g --name es -p 9200:9200 -p 9300:9300 --volume /deta/es:/usr/share/elasticsearch/data elasticsearch
