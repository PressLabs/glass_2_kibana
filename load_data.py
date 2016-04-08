import base64
import datetime
import hashlib
import itertools
import json
import logging
import os
import platform
import signal
import string
import time
import urlparse

import chardet
import pyelasticsearch as es
import requests


VERSION = '20160408-0'
HOST = platform.node().split('.', 1)[0]


def mapping(es_type="string", analyzed=False, **kwargs):
    schema = {
        "type": es_type,
    }
    if analyzed is False:
        schema["index"] = "not_analyzed"
    schema.update(kwargs)
    return schema


def prepare_line(line):
    try:
        record = json.loads(line)
    except ValueError:
        logging.error("got malformed line: %s", line)
        return
    t_stamp = record['time']
    if not t_stamp.endswith('+00:00'):
        raise AssertionError("timezone aware timestamp detected! {}".format(record))
    t_stamp = datetime.datetime.strptime(t_stamp[:-6], "%Y-%m-%dT%H:%M:%S")
    record["time"] = t_stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    record["index_name"] = t_stamp.strftime("%Y.%m.%d")
    uri = record.pop('request_uri', None)
    if uri is not None:
        record['uri'] = uri
    return record


class RequestError(Exception):
    def __init__(self, message, status_code):
        self.status_code = status_code
        super(RequestError, self).__init__(message)


class Indexer(object):
    BATCH_SIZE = 2000
    def __init__(self, es_urls=None, development=False):
        self.client = es.ElasticSearch(urls=es_urls)
        self.es_urls = es_urls
        self._index_name = None
        self._buffer = []
        self._event_index = 0
        self._id_suffix = None
        self._id_prefix = None
        self._reset_sequence = False
        self._fe = None
        self.development = development
        self.create_template()

    def _get_template_version(self):
        try:
            template = self._request('get', '_template/logstash?pretty').json()
        except RequestError as err:
            if err.status_code == 404:
                # if the template is missing it's ok
                return
            else:
                raise
        return template['logstash']['mappings']['logs']['_meta']['schema_version']

    def create_template(self):
        version = self._get_template_version()
        if version and version > VERSION:
            logging.error("Indexer version older than mapping version!")
            return
        url = '_template/logstash?pretty'
        template = {
            "template": "logstash-*",
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                "index.codec": "best_compression",
                "refresh_interval": "1s",
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
            },
            "mappings": {
                "logs": {
                    "_meta": {
                        "schema_version": VERSION,
                    },
                    # ignore fields if not in mapping
                    "dynamic": "false",
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
                        "cache_zone": mapping(),
                        "cache_key": mapping(),
                        "request_length": mapping('integer'),
                        "instance_ref": mapping(),
                        "status": mapping('integer'),
                        "request_method": mapping(),
                        "cache_generated": mapping('date', format='epoch_second'),
                        "user_agent": mapping(analyzed=True),
                        "instance": mapping(),
                        "time": mapping('date'),
                        "cache_ttl": mapping('integer'),
                        "variant": mapping(),
                        "remote_addr": mapping('ip'),
                        "fe": mapping(),
                        "referer": mapping(),
                    },
                }
            },
        }
        return self._request('put', url, template)

    def _request(self, method, url, data=None):
        method_func = getattr(requests, method.lower())
        if url.startswith('/'):
            url = url[1:]
        if data is not None:
            data = json.dumps(data)
        for es_url in self.es_urls:
            (scheme, host, _, _, _) = urlparse.urlsplit(es_url)
            full_url = "{}://{}/{}".format(scheme or "http://", host, url)
            try:
                resp = method_func(full_url, data=data)
                if resp.status_code == 200:
                    return resp
                else:
                    raise RequestError(
                        "Error: {} {} failed with status: {} response was:\n{}".format(
                            method.upper(), url, resp.status_code, resp.content),
                        status_code=resp.status_code)
            except requests.ConnectionError as err:
                logging.warning("could not connect to %s, trying next url")
        else:
            raise requests.ConnectionError("Failed to connect to any url: %r", self.es_urls)

    def _reset_id(self, date_time_str):
        """
        Generate a starting sequence based on the hostname and seconds since midnight of the event
        This means we should generate the same id's and it should be safe to re-process the same
        log file several times and not duplicate events.

        If we ever move away from one index per day this will cause collisions!

        Read this for tips about choosing a performace-friendly id:
        http://blog.mikemccandless.com/2014/05/choosing-fast-unique-identifier-uuid.html
        """
        machine_part = base64.b64encode(small_digest(HOST, 1)).rstrip('=')
        dtime = datetime.datetime.strptime(date_time_str, "%Y-%m-%dT%H:%M:%SZ")
        day_start = datetime.datetime(dtime.year, dtime.month, dtime.day, tzinfo=dtime.tzinfo)
        delta = int((dtime - day_start).total_seconds())
        # delta can be at most 24 * 3600 which fist in 2 bytes
        date_part = chr(delta >> 8) + chr(delta & 255)
        date_part = base64.b64encode(date_part).rstrip('=')
        self._id_suffix = machine_part
        self._id_prefix = date_part
        self._event_index = 0

    def _delete_index(self, index_name):
        try:
            self.client.delete_index(index_name)
            print 'deleted'
        except:
            pass

    def create_index(self, index_name):
        if self.development:
            self._delete_index(index_name)
        try:
            self.client.create_index(index_name)
        except:
            pass
        return self

    def flush_buffer(self):
        if len(self._buffer) == 0:
            return
        self.client.bulk(
            (self.client.index_op(doc, id=doc.pop('_id'))
             for doc in self._buffer),
            index=self._index_name,
            doc_type="logs")
        self._buffer = []

    def index(self, event):
        event_index_name = "logstash-" + event.pop("index_name")
        assert event['time']
        if self._index_name != event_index_name or self._reset_sequence:
            # switch to next index
            self._reset_id(event['time'])
            self.flush_buffer()
            self._index_name = event_index_name
            self._reset_sequence = False
            self.create_index(self._index_name)
        event['fe'] = self._fe
        event['_id'] = '{}{:08x}{}'.format(
            self._id_prefix, self._event_index, self._id_suffix)
        self._event_index += 1
        self._buffer.append(event)
        if len(self._buffer) >= self.BATCH_SIZE:
            self.flush_buffer()

    def file_switched(self):
        """Flush buffer and reset indexing sequence
        This ensures re-processing a log file is idempotent
        """
        self.flush_buffer()
        self._reset_sequence = True


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
    NOAPPEND = False

    def __init__(self, f_name, idle_callback, file_switch_callback):
        self.f_name = f_name
        self.inode = None
        self.idle_callback = idle_callback
        self.file_switch_callback = file_switch_callback

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
                                logging.debug("file switch")
                                self.file_switch_callback()
                            else:
                                if self.NOAPPEND:
                                    # we're in development mode, just exit now
                                    return
                                # wait for more data to be written to the file
                                self.idle_callback()
                                time.sleep(1)
                        else:
                            yield line
            except IOError as err:
                if err.strerror != 'No such file or directory':
                    raise
            time.sleep(1)


def main_loop(args):
    indexer = Indexer(es_urls=args.es_urls)
    data = FileReader(args.input,
                      idle_callback=indexer.flush_buffer,
                      file_switch_callback=indexer.file_switched)
    if args.development is True:
        data.NOAPPEND = True
        indexer.development = True
    for line in data:
        try:
            line = unicode(line, 'utf-8')
        except UnicodeDecodeError:
            guess = chardet.detect(line)['encoding']
            line = unicode(line, guess)
        event = prepare_line(line)
        if event is not None:
            indexer.index(event)
    indexer.flush_buffer()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="push glass logs to elasticsearch")
    parser.add_argument('--es-url', dest='es_urls', nargs='+', type=str)
    parser.add_argument('--input', dest='input', default='/var/lib/glass/access.log')
    parser.add_argument('--development', dest='development', action='store_true')
    args = parser.parse_args()

    level = logging.DEBUG if args.development else logging.WARN
    logging_options = dict(
        format="%(asctime)s %(levelname)s %(message)s",
        level=level
    )
    logging.basicConfig(**logging_options)
    logging.getLogger("elasticsearch.trace").setLevel(logging.WARN)
    logging.getLogger("elasticsearch").setLevel(logging.WARN)
    main_loop(args)


if __name__ == '__main__':
    main()
