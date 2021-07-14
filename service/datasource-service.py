from functools import wraps
from flask import Flask, request, Response, abort
from datetime import datetime, timedelta
from dateutil.parser import parse
import os

import json
import pytz
from simple_salesforce import Salesforce, SalesforceError, SalesforceResourceNotFound
import iso8601
import logging
from collections import OrderedDict

app = Flask(__name__)

logger = None

SF_OBJECTS_CONFIG =  json.loads(os.environ.get("SF_OBJECTS_CONFIG","{}"))

def datetime_format(dt):
    return '%04d' % dt.year + dt.strftime("-%m-%dT%H:%M:%SZ")

def to_transit_datetime(dt_int):
    return "~t" + datetime_format(dt_int)

def get_var(var, scope=None, is_required=False):
    envvar = None
    if (scope is None or scope=="REQUEST"):
        envvar = request.args.get(var)
    elif (scope is None or scope=="ENV") and var.upper() in os.environ:
        envvar = os.environ.get(var.upper())
    if is_required and envvar is None:
        abort(400, "cannot read required '%s' from request params or envvars" % (var.upper()))
    return envvar

class DataAccess:
    def sesamify(self, entity, datatype=None):
        entity.update({"_id": entity["Id"]})
        entity.update({"_updated": "%s" % entity["LastModifiedDate"]})

        for property, value in entity.items():
            schema = [item for item in self._entities.get(datatype, []) if item.get("name") == property]
            if value and len(schema) > 0 and "type" in schema[0] and schema[0]["type"] == "datetime":
                entity[property] = to_transit_datetime(parse(value))

        return entity

    def __init__(self):
        self._entities = {}

    def get_entities(self, since, datatype, sf, objectkey=None):
        if self._entities.get(datatype, []) == []:
            try:
                fields = getattr(sf, datatype).describe()["fields"]
            except SalesforceResourceNotFound as e:
                abort(404)
            self._entities[datatype] = fields
        if objectkey:
            try:
                return self.get_entitiesdata(datatype, since, sf, objectkey)
            except SalesforceResourceNotFound as e:
                abort(404)
        if since is None:
            return self.get_entitiesdata(datatype, since, sf)
        else:
            return [entity for entity in self.get_entitiesdata(datatype, since, sf) if entity["_updated"] > since]

    def get_entitiesdata(self, datatype, since, sf, objectkey=None):

        now = datetime.now(pytz.UTC)
        entities = []
        end = datetime.now(pytz.UTC)  # we need to use UTC as salesforce API requires this
        logger.debug(f"objectkey={objectkey}, datatype={datatype}")
        if objectkey:
            obj = getattr(sf, datatype).get(objectkey)
            return [self.sesamify(obj, datatype)]
        elif since is None:
            #fields = getattr(sf, datatype).describe()["fields"]
            result = [x['Id'] for x in sf.query_all("SELECT Id FROM %s" % (datatype))["records"]]
        else:
            start = iso8601.parse_date(since)
            if start < now + timedelta(days=-30):
                abort(400, "'since' cannot be more than 30 days ago")
            if getattr(sf, datatype):
                if end > (start + timedelta(seconds=60)):
                    result = getattr(sf, datatype).updated(start, end)["ids"]
                    deleted = getattr(sf, datatype).deleted(start, end)["deletedRecords"]
                    for e in deleted:
                        c = OrderedDict({"_id": e["id"]})
                        c.update({"_updated": "%s" % e["deletedDate"]})
                        c.update({"_deleted": True})
                        entities.append(c)
        if result:
            for e in result:
                c = getattr(sf, datatype).get(e)
                entities.append(self.sesamify(c, datatype))
        return entities

data_access_layer = DataAccess()


def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth and not(get_var("USERNAME", "ENV") and get_var("PASSWORD", "ENV") and get_var("SECURITY_TOKEN", "ENV")):
            return authenticate()
        return f(*args, **kwargs)

    return decorated

def get_sf():
    if request.authorization:
        auth = request.authorization
    else:
        auth =  {
            "username": get_var("SECURITY_TOKEN", "ENV") + "\\" + get_var("USERNAME", "ENV"),
            "password": get_var("PASSWORD", "ENV")
            }
    token, username = auth['username'].split("\\", 1)
    password = auth['password']

    instance = get_var('instance') or "prod"
    if instance == "sandbox":
        sf = Salesforce(username, password, token, domain='test')
    else:
        sf = Salesforce(username, password, token)
    return sf

@app.route('/<datatype>', methods=['GET'], endpoint="get_all")
@app.route('/<datatype>/<objectkey>', methods=['GET'], endpoint="get_by_id")
@app.route('/<datatype>/<ext_id_field>/<ext_id>', methods=['GET'], endpoint="get_by_ext_id")
@requires_auth
def get_entities(datatype, objectkey=None, ext_id_field=None, ext_id=None):
    try:
        since = request.args.get('since')
        sf = get_sf()
        if request.endpoint == "get_by_ext_id":
            objectkey = f"{ext_id_field}/{ext_id}"
        entities = sorted(data_access_layer.get_entities(since, datatype, sf, objectkey), key=lambda k: k["_updated"])
        return Response(json.dumps(entities), mimetype='application/json')
    except SalesforceError as err:
        return Response(json.dumps({"resource_name": err.resource_name, "content": err.content, "url": err.url}),
            mimetype='application/json',
            status=err.status)
    except Exception as err:
        return Response(str(err), mimetype='plain/text', status=500)

@app.route('/<datatype>', methods=["POST", "PUT", "PATCH", "DELETE"], endpoint = "crud_all")
@app.route('/<datatype>/<objectkey>', methods=['POST', "PUT", "PATCH", "DELETE"], endpoint="crud_by_id")
@app.route('/<datatype>/<ext_id_field>/<ext_id>', methods=["POST", "PUT", "PATCH", "DELETE"], endpoint="crud_by_ext_id")
@requires_auth
def receiver(datatype, objectkey=None, ext_id_field=None, ext_id=None):
    try:
        entities = request.get_json()
        sf = get_sf()
        if request.endpoint == "crud_by_ext_id":
            objectkey = f"{ext_id_field}/{ext_id}"
        if getattr(sf, datatype):
            transform(datatype, entities, sf, operation_in=request.method, objectkey_in=objectkey)
        return Response("", mimetype='application/json')
    except SalesforceError as err:
        logger.exception(err)
        return Response(json.dumps({"resource_name": err.resource_name, "content": err.content, "url": err.url}),
            mimetype='application/json',
            status=err.status)
    except Exception as err:
        logger.exception(err)
        return Response(str(err), mimetype='plain/text', status=500)

@app.route('/sf/tooling/<path:path>', methods=["GET", "POST", "DELETE"], endpoint="tooling_execute")
@requires_auth
def tooling_execute(path):
    try:
        sf = get_sf()
        data = request.get_json()
        response_json = sf.toolingexecute(
            path,
            method=request.method,
            data=data)
        if request.method == "GET":
            return Response(json.dumps(data_access_layer.sesamify(response_json)), mimetype='application/json')
        else:
            return Response(json.dumps(response_json), mimetype='application/json')
    except SalesforceError as err:
        logger.exception(err)
        return Response(json.dumps({"resource_name": err.resource_name, "content": err.content, "url": err.url}),
            mimetype='application/json',
            status=err.status)
    except Exception as err:
        logger.exception(err)
        return Response(str(err), mimetype='plain/text', status=500)

@app.route('/ValueSet/CustomField/<field_id>', methods=["GET", "POST", "DELETE"], endpoint="custom_valueset")
@app.route('/ValueSet/GlobalValueSet/<field_id>', methods=["GET", "POST", "DELETE"], endpoint="global_valueset")
@requires_auth
def valueset_execute(field_id):
    try:
        path = request.path.replace("/ValueSet", "")
        sf = get_sf()       
        data = request.get_json()
        if request.method == "GET":
            tooling_api_response = sf.toolingexecute(
                f"sobjects{path}",
                method=request.method,
                data=data)
            response_data = {"path":path, "_id": path}
            metadata = tooling_api_response.get("Metadata",{})
            if request.endpoint == "global_valueset":
                response_data["valueSet"] = metadata.get("customValue")
                response_data["fullName"] = metadata.get("masterLabel")
                response_data["sorted"] = metadata.get("sorted")
            elif request.endpoint == "custom_valueset":
                response_data["valueSet"] = metadata.get("valueSet",{}).get("valueSetDefinition",{}).get("value",[])
                response_data["fullName"] = tooling_api_response.get("FullName")
                response_data["sorted"] = metadata.get("valueSet",{}).get("valueSetDefinition",{}).get("sorted")
            return Response(json.dumps(response_data), mimetype='application/json')
        elif request.method == "DELETE":
            tooling_api_response = sf.toolingexecute(
                f"sobjects{path}",
                method=request.method,
                data=data)

            return Response(json.dumps(response_json), mimetype='application/json')
    except SalesforceError as err:
        logger.exception(err)
        return Response(json.dumps({"resource_name": err.resource_name, "content": err.content, "url": err.url}),
            mimetype='application/json',
            status=err.status)
    except Exception as err:
        logger.exception(err)
        return Response(str(err), mimetype='plain/text', status=500)

def transform(datatype, entities, sf, operation_in="POST", objectkey_in=None):
    def _get_object_key(entity, objectkey_in=None):
        '''if 'Id' is specified, use 'Id' as key,
            else pick the first external id field that has a value'''
        key_field = "Id"
        key = None
        if entity.get(key_field):
            key = entity[key_field]
        elif datatype in SF_OBJECTS_CONFIG:
            for k in SF_OBJECTS_CONFIG[datatype]["ordered_key_fields"]:
                if entity.get(k):
                    key_field = k
                    key = f"{key_field}/{entity[key_field]}"
                    break

        key = key or objectkey_in
        if not key:
            abort(500,"cannot figure out the objectkey for %s" % (entity))
        #remove fields starting with '_'
        d = []
        for p in entity.keys():
            if p.startswith("_") or p in ["Id", key_field]:
                d.append(p)
        for p in d:
            del(entity[p])

        return entity, key

    global ids
    c = None
    listing = []
    if not isinstance(entities, list):
        listing.append(entities)
    else:
        listing = entities
    for e in listing:
        operation = "DELETE" if e.get("_deleted", False) or operation_in == "DELETE" else operation_in
        object, objectkey = _get_object_key(e, objectkey_in)

        app.logger.debug(f"performing {operation} on {datatype}/{objectkey}")
        if operation == "DELETE":
            try:
                getattr(sf, datatype).delete(objectkey)
            except Exception as err:
                app.logger.debug(f"{datatype}/{objectkey} received exception of type {type(err).__name__}")
        else:
            getattr(sf, datatype).upsert(objectkey, object)


if __name__ == '__main__':
    # Set up logging
    format_string = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logger = logging.getLogger('salesforce-microservice')

    # Log to stdout
    stdout_handler = logging.StreamHandler()
    stdout_handler.setFormatter(logging.Formatter(format_string))
    logger.addHandler(stdout_handler)

    logger.setLevel(logging.DEBUG)

    app.run(debug=True, host='0.0.0.0')

