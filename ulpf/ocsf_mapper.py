import json

class OCSFMapper:
    """Translates flat regex extractions into nested OCSF compliant JSON."""

    @staticmethod
    def map_event(category: str, extracted_fields: dict) -> str:
        category = category.upper()
        
        if category == "AUTHENTICATION":
            # OCSF Class 3002: Authentication
            ocsf_payload = {
                "class_uid": 3002,
                "class_name": "Authentication",
                "category_uid": 3,
                "category_name": "Identity & Access Management",
                "activity_name": extracted_fields.get("action", "unknown"),
                "status_detail": extracted_fields.get("status", "unknown"),
                "user": {
                    "name": extracted_fields.get("user", "unknown"),
                    "domain": extracted_fields.get("domain", "LOCAL")
                }
            }
            
        elif category == "WEB":
            # OCSF Class 4002: HTTP Activity
            ocsf_payload = {
                "class_uid": 4002,
                "class_name": "HTTP Activity",
                "category_uid": 4,
                "category_name": "Network Activity",
                "src_endpoint": {
                    "ip": extracted_fields.get("src_ip", "0.0.0.0")
                },
                "http_request": {
                    "http_method": extracted_fields.get("method", "unknown"),
                    "url": {
                        "path": extracted_fields.get("url", "unknown")
                    }
                },
                "http_response": {
                    "status_code": extracted_fields.get("status", 0)
                }
            }
            
        else:
            # Default to OCSF Class 4001: Network Activity
            ocsf_payload = {
                "class_uid": 4001,
                "class_name": "Network Activity",
                "category_uid": 4,
                "category_name": "Network Activity",
                "activity_name": extracted_fields.get("action", "unknown"),
                "connection_info": {
                    "protocol_name": extracted_fields.get("proto", "unknown")
                },
                "src_endpoint": {
                    "ip": extracted_fields.get("src_ip", "0.0.0.0")
                },
                "dst_endpoint": {
                    "ip": extracted_fields.get("dst_ip", "0.0.0.0")
                }
            }

        return json.dumps(ocsf_payload)