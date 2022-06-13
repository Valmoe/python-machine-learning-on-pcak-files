from elasticsearch import Elasticsearch, helpers
import configparser

config = configparser.ConfigParser()
print(config.read('elastic_connect.ini'))
es = Elasticsearch(cloud_id=config['ELASTIC']['cloud_id'],http_auth=(config['ELASTIC']['user'], config['ELASTIC']['password']))
print(es.info())



