[![Build Status](https://travis-ci.org/sesam-community/salesforce.svg?branch=master)](https://travis-ci.org/sesam-community/salesforce)

# salesforce
Sesam-Salesforce connector that can be used to:
  * get/delete/upsert objects
  * get/delete/upsert valuesets(a.k.a. picklist)
  * perform tooling API operations

## ENV VARIABLES

| CONFIG_NAME        | DESCRIPTION           | IS_REQUIRED  |DEFAULT_VALUE|
| -------------------|---------------------|:------------:|:-----------:|
| USERNAME | username for login | yes | n/a |
| PASSWORD | password for login | yes | n/a |
| SECURITY_TOKEN | security token for login. obtained from the profile page of the user | yes | n/a |
| LOGIN_CONFIG | a dict with keys _USERNAME, PASSWORD, SECURITY_TOKEN_ so that login details are kept in only 1 secret | yes | n/a |
| WEBFRAMEWORK | set to 'FLASK' to use flask, otherwise it will run on cherrypy | no | n/a |
| LOG_LEVEL | LOG_LEVEL. one of [CRITICAL\|ERROR\|WARNING\|INFO\|DEBUG] | no | 'INFO' |
| INSTANCE | salesforce instance. set to 'sandbox' to work on test domain. Otherwise it will be non-test domain. | no | 'prod' |
| VALUESET_LIST | concatenated valueset ids to fetch on '/ValueSet/' endpoint. Values will be splitt by the delimiter specified in 'DELIMITER' env var| no | n/a |
| DELIMITER | delimiter to be used when splitting envvar values where applicable | no | '\|' |
| SF_OBJECTS_CONFIG | dict for object level customizations. see schemas section for description. | no | n/a |


## ENDPOINTS

 1. `/<datatype>`, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
 
    By default _Id_ is used to match target object. If _Id_ is not available to Sesam, the _SF_OBJECTS_CONFIG_ envvar can be configured for alternative match keys.
    
    * "GET": returns all data(upserted and deleted) of type _datatype_._Id_ and _LastModifiedDate_ is set as _\_id_ and _\_updated_, respectively.
    * "POST", "PUT", "PATCH": upserts objects or deletes if _\_deleted_ is true. Accepts dict or list of dicts. 
    * "DELETE": deletes incoming objects.

    #### query params
    `since`: Optional. Data updated after _since_ value will be delivered. CAnnot be older then 30 days ago due to Salesforce REST API limitations.

___

 2. `/<datatype>/<ext_id_field>/<ext_id>`, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
 
    Same as point 1, but here the the the objectkey(externalkey here) can additionally be read from the url. 

___    

3. `/<datatype>/<objectkey>`, methods=["GET", "POST", "PUT", "PATCH", "DELETE"]
	
    Same as point 2, but here the the the objectkey(genuine objectkey/Id) can additionally be read from the url. 
___  
 4. `/ValueSet`, methods=["GET","POST"]
	
    * "GET": returns all valuesets that are specified in _VALUESET\_LIST_ envvar
    * "POST": Upserts values to valuesets. See _ValueSet_ below in schemas section for description of payload.

    Note that a value is disabled via _isActive_ flag in the json.
    
    #### query params
     * `do_refine`: Optional. If equals to one of _"0", "false", "no"_ case-insensitively, the original payload will be returned in _data_ field of the response.
       Otherwise, only the valueset section.
___
 5. `/ValueSet/`, methods=["GET", "POST"]

    Same as 4. (Sesam required the trailing slach for some reason.)
___    
 6. `/ValueSet/CustomField/<field_id>`, methods=["GET", "POST"]

	  Same as 4, but for single valueset that is customfield.
___    
 7. `/ValueSet/GlobalValueSet/<field_id>`, methods=["GET", "POST"]
 
    Same as 6, but for single valueset that is global valueset.
___    
 8. `/sf/tooling/<path:path>`, methods=["GET", "POST", "DELETE", "PATCH", "PUT"]

    This is endpoint that makes available the [Salesforce tooling API](https://developer.salesforce.com/docs/atlas.en-us.api_tooling.meta/api_tooling/intro_api_tooling.htm).
___

## Schemas

 * SF_OBJECTS_CONFIG is a dict where keysa are sobject names that to be customized. Value is a dict for different customizations available:
    * _ordered_key_fields_: a ordered list of strings. Effective when setting _\_id_ value and _Id_ is not available. The first field that reveals a non-null value will be used to ser _\_id_. 
```
{
        "aadgroup__c": {
            "ordered_key_fields": [
                "sesam_ext_id__c",
                "some_ext_id__c"
            ]
        },
        "Product2":{
            "ordered_key_fields": [
                "sesam_ext_id__c",
                "some_ext_id__c"
            ]
        }
    }
```    

 * ValueSet:
```
[
	{
		"data": [
			{
				"color": null,
				"default": false,
				"description": null,
				"isActive": true,
				"label": "mylabel",
				"urls": null,
				"valueName": "myvalue"
			}
		]
	}
]
```
