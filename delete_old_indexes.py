"""Simple script to delete older logstash indexes
"""
import httplib
import json
import argparse
import logging


def get_indexes(url):
    conn = httplib.HTTPConnection(url)
    try:
        conn.request('GET', '/_stats')
        response = conn.getresponse()
        if int(response.status) != 200:
            logging.error('failed to get /_stats: %s %s', response.status, response.reason)
        metadata = json.loads(response.read())
    finally:
        conn.close()
    return sorted(
        [name for name in metadata['indices'].keys()
         if name.startswith('logstash-')])


def delete_older(url, keep_last=11):
    for name in get_indexes(url)[:-keep_last]:
        logging.warning('deleting log %s', name)
        conn = httplib.HTTPConnection(url)
        try:
            conn.request('DELETE', '/{}'.format(name))
            resp = conn.getresponse()
        finally:
            conn.close()
        if int(resp.status) != 200:
            logging.error('failed to delete /%s: %s %s',
                          name, resp.status, resp.reason)



def main():
    logging_options = dict(
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.INFO
    )
    logging.basicConfig(**logging_options)
    logging.getLogger("elasticsearch.trace").setLevel(logging.WARN)
    logging.getLogger("elasticsearch").setLevel(logging.WARN)
    parser = argparse.ArgumentParser(description="delete old logs")
    parser.add_argument('--es-url', dest='es_url', type=str, default='localhost:9200')
    args = parser.parse_args()
    url = args.es_url
    delete_older(url)

if __name__ == '__main__':
    main()
