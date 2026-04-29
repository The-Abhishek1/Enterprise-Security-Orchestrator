# src/workers/spec_parser.py
"""
API Spec Parser — parses OpenAPI 3.0, Swagger 2.0, and Postman Collection v2.x
into a normalised internal endpoint model for the API security tester.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from src.utils.logging import logger


@dataclass
class Param:
    name:     str
    location: str          # query | path | header | cookie | body
    required: bool = False
    type:     str  = "string"
    example:  Any  = None


@dataclass
class Endpoint:
    method:        str
    path:          str
    operation_id:  str            = ""
    description:   str            = ""
    params:        List[Param]    = field(default_factory=list)
    body_schema:   Optional[Dict] = None
    auth_required: bool           = False
    tags:          List[str]      = field(default_factory=list)
    base_url:      str            = ""


def parse_spec(raw: "str | dict", base_url_override: str = "") -> List[Endpoint]:
    """Auto-detect format and parse into Endpoint list."""
    if isinstance(raw, str):
        try:
            spec = json.loads(raw)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")
    else:
        spec = raw

    if "openapi" in spec and str(spec.get("openapi", "")).startswith("3"):
        endpoints = _parse_openapi3(spec)
    elif "swagger" in spec and str(spec.get("swagger", "")).startswith("2"):
        endpoints = _parse_swagger2(spec)
    elif "info" in spec and "item" in spec:
        endpoints = _parse_postman(spec)
    else:
        raise ValueError("Unrecognised spec format. Supported: OpenAPI 3.x, Swagger 2.0, Postman v2.x")

    if base_url_override:
        for ep in endpoints:
            ep.base_url = base_url_override.rstrip("/")

    logger.info(f"[spec-parser] Parsed {len(endpoints)} endpoints")
    return endpoints


# ── OpenAPI 3.x ──────────────────────────────────────────────────────────────

def _parse_openapi3(spec: Dict) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    servers  = spec.get("servers") or []
    base_url = (servers[0].get("url") or "").rstrip("/") if servers else ""
    global_security = spec.get("security") or []

    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        path_params = _params_oa3(path_item.get("parameters") or [], spec)

        for method in ("get","post","put","patch","delete","head","options"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue

            params = list(path_params) + _params_oa3(op.get("parameters") or [], spec)

            body_schema = None
            for mime in ("application/json","application/x-www-form-urlencoded","multipart/form-data"):
                content = (op.get("requestBody") or {}).get("content") or {}
                if mime in content:
                    s = content[mime].get("schema")
                    body_schema = _resolve_ref(s, spec) if s else None
                    break

            op_security = op.get("security", global_security)
            endpoints.append(Endpoint(
                method=method.upper(), path=path,
                operation_id=op.get("operationId", f"{method.upper()}_{path}"),
                description=(op.get("summary") or op.get("description") or "")[:200],
                params=params, body_schema=body_schema,
                auth_required=bool(op_security),
                tags=op.get("tags") or [], base_url=base_url,
            ))
    return endpoints


def _params_oa3(raw: list, spec: Dict) -> List[Param]:
    params = []
    for p in raw:
        if isinstance(p, dict) and "$ref" in p:
            p = _resolve_ref(p, spec) or {}
        if not isinstance(p, dict):
            continue
        schema  = _resolve_ref(p.get("schema") or {}, spec) or {}
        example = p.get("example") or schema.get("example") or schema.get("default")
        params.append(Param(
            name=p.get("name",""), location=p.get("in","query"),
            required=bool(p.get("required")), type=schema.get("type","string"),
            example=example,
        ))
    return params


# ── Swagger 2.0 ──────────────────────────────────────────────────────────────

def _parse_swagger2(spec: Dict) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    host     = spec.get("host","localhost")
    basepath = (spec.get("basePath") or "/").rstrip("/")
    scheme   = (spec.get("schemes") or ["https"])[0]
    base_url = f"{scheme}://{host}{basepath}"
    global_security = spec.get("security") or []

    for path, path_item in (spec.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        path_params = _params_sw2(path_item.get("parameters") or [])

        for method in ("get","post","put","patch","delete","head","options"):
            op = path_item.get(method)
            if not isinstance(op, dict):
                continue
            params = list(path_params) + _params_sw2(op.get("parameters") or [])
            body_params = [p for p in params if p.location == "body"]
            params      = [p for p in params if p.location != "body"]
            body_schema = {"type":"object"} if body_params else None

            op_security = op.get("security", global_security)
            endpoints.append(Endpoint(
                method=method.upper(), path=path,
                operation_id=op.get("operationId", f"{method.upper()}_{path}"),
                description=(op.get("summary") or op.get("description") or "")[:200],
                params=params, body_schema=body_schema,
                auth_required=bool(op_security),
                tags=op.get("tags") or [], base_url=base_url,
            ))
    return endpoints


def _params_sw2(raw: list) -> List[Param]:
    return [
        Param(name=p.get("name",""), location=p.get("in","query"),
              required=bool(p.get("required")), type=p.get("type","string"),
              example=p.get("default"))
        for p in raw if isinstance(p, dict)
    ]


# ── Postman v2.x ─────────────────────────────────────────────────────────────

def _parse_postman(spec: Dict) -> List[Endpoint]:
    endpoints: List[Endpoint] = []
    _walk(spec.get("item") or [], endpoints)
    return endpoints


def _walk(items: list, out: List[Endpoint]):
    for item in items:
        if not isinstance(item, dict):
            continue
        if "item" in item:
            _walk(item["item"], out)
        elif "request" in item:
            ep = _postman_ep(item)
            if ep:
                out.append(ep)


def _postman_ep(item: Dict) -> Optional[Endpoint]:
    req = item.get("request") or {}
    if not isinstance(req, dict):
        return None
    method = (req.get("method") or "GET").upper()
    url    = req.get("url") or {}
    if isinstance(url, str):
        parts = url.split("/")
        base  = "/".join(parts[:3])
        path  = "/" + "/".join(parts[3:]).split("?")[0]
        query: list = []
    else:
        pp    = url.get("path") or []
        path  = "/" + "/".join(p if isinstance(p,str) else p.get("value","") for p in pp)
        rraw  = url.get("raw") or ""
        base  = "/".join(rraw.split("/")[:3])
        query = url.get("query") or []

    params: List[Param] = []
    for q in query:
        if isinstance(q, dict) and not q.get("disabled"):
            params.append(Param(name=q.get("key",""), location="query", example=q.get("value")))
    for h in (req.get("header") or []):
        if isinstance(h, dict) and not h.get("disabled"):
            params.append(Param(name=h.get("key",""), location="header", example=h.get("value")))

    body_schema = None
    body = req.get("body") or {}
    if body.get("mode") == "raw" and body.get("raw"):
        try:
            body_schema = {"type":"object","example": json.loads(body["raw"])}
        except Exception:
            body_schema = {"type":"string"}

    return Endpoint(
        method=method, path=path or "/",
        operation_id=item.get("name", f"{method}_{path}"),
        description=(req.get("description") or "")[:200] if isinstance(req.get("description"), str) else "",
        params=params, body_schema=body_schema, base_url=base,
    )


# ── $ref resolver ────────────────────────────────────────────────────────────

def _resolve_ref(obj: Any, spec: Dict, depth: int = 0) -> Any:
    if depth > 5 or not isinstance(obj, dict) or "$ref" not in obj:
        return obj
    ref = obj["$ref"]
    if not ref.startswith("#/"):
        return obj
    node = spec
    for part in ref.lstrip("#/").split("/"):
        node = (node or {}).get(part.replace("~1","/").replace("~0","~"))
        if node is None:
            return {}
    return _resolve_ref(node, spec, depth + 1)


def endpoint_to_dict(ep: Endpoint) -> Dict:
    return {
        "method": ep.method, "path": ep.path,
        "operationId": ep.operation_id, "description": ep.description,
        "baseUrl": ep.base_url, "authRequired": ep.auth_required,
        "tags": ep.tags,
        "params": [{"name":p.name,"in":p.location,"required":p.required,
                    "type":p.type,"example":p.example} for p in ep.params],
        "bodySchema": ep.body_schema,
    }
