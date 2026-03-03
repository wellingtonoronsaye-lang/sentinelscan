from flask_restx import fields

from app.scan.blueprint import api


scan_request = api.model("ScanRequest", {
    "ip": fields.String(
        required=True,
        description="IPv4 address to scan",
        example="8.8.8.8"
    )
})

source_result = api.model("SourceResult", {
    "source":     fields.String(description="Connector name"),
    "ioc":        fields.String(description="Scanned value"),
    "ioc_type":   fields.String(description="Type of IoC"),
    "verdict":    fields.String(description="malicious | suspicious | clean | unknown"),
    "confidence": fields.Float(description="0.0 – 1.0"),
    "details":    fields.Raw(description="Source-specific metadata"),
    "error":      fields.String(description="Error message, if any"),
})

scan_response = api.model("ScanResponse", {
    "ioc":             fields.String(description="Scanned value"),
    "ioc_type":        fields.String(description="ip"),
    "overall_verdict": fields.String(description="Aggregated verdict across all sources"),
    "sources_scanned": fields.Integer(description="Number of sources queried"),
    "results":         fields.List(fields.Nested(source_result)),
})