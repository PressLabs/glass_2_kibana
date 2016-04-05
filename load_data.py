import base64
import datetime
import json
import time
import os
import platform
import hashlib
import itertools
import logging

import chardet
import pyelasticsearch as es


HOST = platform.node().split('.', 1)[0]


def mapping(es_type="string", analyzed=False, analyzer=None, index_name=None):
    schema = {
        "type": es_type,
    }
    if analyzed is False:
        schema["index"] = "not_analyzed"
    elif analyzer is not None:
        schema['analyzer'] = analyzer
    return schema


def prepare_line(line):
    record = json.loads(line)
    t_stamp = record['time']
    if not t_stamp.endswith('+00:00'):
        raise AssertionError("timezone aware timestamp detected! {}".format(record))
    t_stamp = datetime.datetime.strptime(t_stamp[:-6], "%Y-%m-%dT%H:%M:%S")
    record["time"] = t_stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    record["index_name"] = t_stamp.strftime("%Y.%m.%d")
    record['uri'] = record.pop('request_uri')
    return record


class Indexer(object):
    BATCH_SIZE = 2000
    def __init__(self, settings=None, es_urls=None):
        self.settings = settings or {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.codec": "best_compression",
            "refresh_interval": "15s",
            "analysis": {
                "tokenizer": {
                    "url_tokenizer": {
                        "type": "pattern",
                        "pattern": "[/?=;&]"
                    },
                },
                "analyzer": {
                    "custom_url": {
                        "type": "custom",
                        "tokenizer": "url_tokenizer",
                    }
                }
            }
        }
        self.client = es.ElasticSearch(urls=es_urls)
        self.index_name = None
        self._buffer = []
        self._event_index = 0
        self._fe = None
        # self._created = set([])

    def _reset_id_prefix(self):
        """generate and set prefix for all ids"""
        machine_prefix = base64.b64encode(small_digest(HOST))[:-1]
        self._fe = machine_prefix
        now = datetime.datetime.now()
        time_prefix = base64.b64encode("".join((chr(now.hour), chr(now.minute), chr(now.second))))
        self._id_prefix = machine_prefix + time_prefix

    def create_index(self, index_name):
        try:
            # self.client.delete_index(index_name)
            self.client.create_index(index_name, self.settings)
            _mapping = {
                "logs": {
                    "properties": {
                        "etag": mapping(),
                        "bytes_sent": mapping('integer'),
                        "request_time": mapping('float'),
                        "request_id": mapping(),
                        "host": mapping(),
                        "request_type": mapping(),
                        "scheme": mapping(),
                        "uri": mapping(
                            analyzed=True,
                            analyzer='custom_url',
                        ),
                        "cache_status": mapping(),
                        "cache_key": mapping(),
                        "request_length": mapping('integer'),
                        "instance_ref": mapping(),
                        "status": mapping('integer'),
                        "request_method": mapping(),
                        "cache_generated": mapping('integer'),
                        "user_agent": mapping(analyzed=True),
                        "instance": mapping(),
                        "time": mapping('date'),
                        "cache_ttl": mapping('integer'),
                        "variant": mapping(),
                        "remote_addr": mapping('ip'),
                        "fe": mapping(),
                    },
                }
            }
            self.client.put_mapping(
                index_name, "logs", _mapping)
        except:
            # TODO: check for index existance instead
            pass
        # self._created.add(index_name)
        # import sys; sys.exit(0)
        return self

    def flush_buffer(self):
        if len(self._buffer) == 0:
            return
        # import ipdb; ipdb.set_trace()
        # assert self.index_name in self._created
        self.client.bulk(
            (self.client.index_op(doc, id=doc.pop('_id'))
             for doc in self._buffer),
            index=self.index_name,
            doc_type="logs")
        self._buffer = []

    def index(self, event):
        event_index_name = "logstash-" + event.pop("index_name")
        if self.index_name != event_index_name:
            # switch to next index
            self.flush_buffer()
            self.index_name = event_index_name
            self._reset_id_prefix()
            self.create_index(self.index_name)
        event['fe'] = self._fe
        event['_id'] = self._id_prefix + '{:06x}'.format(self._event_index)
        self._event_index += 1
        self._buffer.append(event)
        if len(self._buffer) >= self.BATCH_SIZE:
            self.flush_buffer()


def partitions(name, length):
    for i in xrange(0, len(name), length):
        yield [ord(char) for char in name[i:i+length]]


def xor(part1, part2):
    ret = []
    for (c1, c2) in itertools.izip_longest(part1, part2, fillvalue=0):
        ret.append(c1 ^ c2)
    return ret


def small_digest(data, length=3):
    """Get a short digest by xoring together slices of the md5 of data

    Args:
        data (string): The data
        length (number): The length in bytes of the resulting digest
    """
    digest = hashlib.md5(data).digest()
    return "".join(chr(byte) for byte in reduce(xor, partitions(digest, length)))


class FileReader(object):
    def __init__(self, f_name, idle_callback):
        self.f_name = f_name
        self.inode = None
        self.idle_callback = idle_callback

    def __iter__(self):
        while True:
            try:
                with open(self.f_name) as access_log:
                    self.inode = os.fstat(access_log.fileno()).st_ino
                    logging.info("processing file %d", self.inode)
                    file_switched = False
                    while not file_switched:
                        line = access_log.readline()
                        if line == "":
                            if os.stat(self.f_name).st_ino != self.inode:
                                file_switched = True
                            else:
                                self.idle_callback()
                                time.sleep(1)
                        else:
                            yield line
            except IOError as err:
                if err.strerror != 'No such file or directory':
                    raise
            time.sleep(1)


def main(args):
    indexer = Indexer(es_urls=args.es_urls)
    data = FileReader("/var/lib/glass/access.log",
                      idle_callback=indexer.flush_buffer)
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
    logging_options = dict(
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.INFO
    )
    logging.basicConfig(**logging_options)
    logging.getLogger("elasticsearch.trace").setLevel(logging.WARN)
    logging.getLogger("elasticsearch").setLevel(logging.WARN)
    parser = argparse.ArgumentParser(description="push glass logs to elasticsearch")
    parser.add_argument('--es-url', dest='es_urls', nargs='+', type=str)
    args = parser.parse_args()
    main(args)
