import datetime
import json
import time
import os

import chardet
import pyelasticsearch as es


def mapping(es_type="string", analyzed=False):
    schema = {
        "type": es_type,
        # "fielddata": {
        #     "format": "disabled"
        # },
        "fields": {
            "raw": {
                "type": es_type,
                "index": "not_analyzed",
            }
        }
    }
    if analyzed is False:
        schema["index"] = "not_analyzed"
    return schema


def prepare_line(line):
    record = json.loads(line)
    t_stamp = record.pop('time')
    if not t_stamp.endswith('+00:00'):
        raise AssertionError("timezone aware timestamp detected! {}".format(record))
    t_stamp = datetime.datetime.strptime(t_stamp[:-6], "%Y-%m-%dT%H:%M:%S").strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    # record["timestamp"] = time.mktime(t_stamp.timetuple())
    record["timestamp"] = t_stamp
    return record


class Indexer(object):
    BATCH_SIZE = 100
    def __init__(self, settings=None, es_urls=None):
        self.settings = settings or {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.codec": "best_compression",
            "refresh_interval": "60s",
        }
        self.client = es.ElasticSearch(urls=es_urls)
        self.index_name = None
        self._buffer = []

    def create_index(self):
        try:
            self.client.delete_index(self.index_name)
        except:
            pass
        self.client.create_index(self.index_name, self.settings)
        _mapping = {
            "logs": {
                "properties": {
                    # "status": mapping(),
                    # "time":  {"type": "integer"},
                    # "location":  mapping(),
                    # "desc":  mapping(),
                    "bytes_sent": mapping('integer'),
                    "request_time": mapping('float'),
                    "request_id": mapping(),
                    "host": mapping(analyzed=True),
                    "request_type": mapping(),
                    "scheme": mapping(),
                    "request_uri": mapping(analyzed=True),
                    "cache_status": mapping(),
                    "cache_key": mapping(),
                    "request_length": mapping('integer'),
                    "instance_ref": mapping(),
                    "status": mapping('integer'),
                    "request_method": mapping(),
                    "cache_generated": mapping('integer'),
                    "user_agent": mapping(analyzed=True),
                    "instance": mapping(),
                    "timestamp": mapping('date'),
                    "cache_ttl": mapping('integer'),
                    "variant": mapping(),
                    "remote_addr": mapping('ip')
                },
                # 'source': {
                #     'excludes': []
                # }
            }
        }
        # from pprint import pprint
        # pprint(_mapping)
        self.client.put_mapping(
            self.index_name, "logs", _mapping)
        return self

    def flush_buffer(self):
        if len(self._buffer) == 0:
            return
        self.client.bulk_index(self.index_name, "logs", self._buffer)
        self._buffer = []

    def index(self, event):
        date = event["timestamp"][:10].replace("-", ".")
        if self.index_name != "logstash-" + date:
            self.flush_buffer()
            self.index_name = "logstash-" + date
            self.create_index()
        self._buffer.append(event)
        if len(self._buffer) >= self.BATCH_SIZE:
            self.flush_buffer()


class FileReader(object):
    def __init__(self, f_name):
        self.f_name = f_name
        self.inode = None

    def __iter__(self):
        while True:
            with open(self.f_name) as access_log:
                inode = os.fstat(access_log.fileno()).st_ino
                if inode == self.inode:
                    time.sleep(1)
                    continue
                self.inode = inode
                for line in access_log:
                    yield line
            time.sleep(1)


def main(args):
    indexer = Indexer(es_urls=args.es_urls)
    data = FileReader("/var/lib/glass/access.log")
    for line in data:
        try:
            line = unicode(line, 'utf-8')
        except UnicodeDecodeError:
            guess = chardet.detect(line)['encoding']
            line = unicode(line, guess)
        event = prepare_line(line)
        indexer.index(event)
    indexer.flush_buffer()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="push glass logs to elasticsearch")
    parser.add_argument('--es-url', dest='es_urls', nargs='+', type=str)
    args = parser.parse_args()
    main(args)
