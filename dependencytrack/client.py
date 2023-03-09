"""
A dependencytrack client.
"""
import base64
import json
import logging
import re
from pathlib import Path
from typing import Union
from urllib.parse import urlencode, urlparse

import requests

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def fields_filter(data, fields=None):
    if fields and isinstance(data, list):
        return [{k: v for k, v in d.items() if k in fields} for d in data]
    return data


def purl_to_project(purl):
    if not purl.startswith("pkg:maven/"):
        raise NotImplementedError("Only maven purls are supported")
    group_id, project_name, project_version = re.match(
        r"pkg:maven/([^/]+)/([^@]+)@(.+)", purl
    ).groups()
    return group_id, project_name, project_version


class DTProxy:
    preserve_type = False

    def __init__(self, client, path, parent=None, data=None):
        self.client = client
        if parent:
            path = f"{parent}/{path}"
        self.path = path
        self.data = data or {}
        self.uuid = self.data.get("uuid") if isinstance(self.data, dict) else None

    def get(self, uuid, fields=None):
        dpath = f"{self.path}/{uuid}"
        ret = self.client._invoke_("get", dpath, paginated=False, ignore_status=(404,))
        if ret.status_code == 404:
            log.info(f"Could not find {ret.url}")
            return None
        data = ret.json()

        clz = DTProxy
        if "uuid" in data and self.preserve_type:
            clz = self.__class__
        return clz(
            client=self.client, path=dpath, data=fields_filter(data, fields=fields)
        )

    def list(self, fields=None, **kwargs):
        ret = self.client._invoke_(
            "get", f"{self.path}", qp=kwargs, ignore_status=(404,)
        )
        log.debug(f"Retrieved items from {ret.url} {ret.content}")
        if ret.status_code == 404:
            log.info(f"Could not find {ret.url}")
            return None
        data = ret.json()
        return fields_filter(data, fields=fields)

    def create(self, entry):
        ret = self.client._invoke_("put", f"{self.path}", json=entry)
        data = ret.json()
        if uuid := data.get("uuid"):
            path = f"{self.path}/{uuid}"
        else:
            path = self.path

        clz = DTProxy
        if "uuid" in data and self.preserve_type:
            clz = self.__class__

        return clz(client=self.client, path=path, data=data)

    def upload(self, bom_payload):
        if not self.path.endswith("bom"):
            raise ValueError("Can only upload boms")
        ret = self.client._invoke_("put", f"{self.path}", json=bom_payload)
        return ret.json()

    def update(self, uuid, entry):
        ret = self.client._invoke_("patch", f"{self.path}/{uuid}", json=entry)
        return ret.json()

    def post(self, **kwargs):
        ret = self.client._invoke_("post", f"{self.path}", **kwargs)
        return ret.json()

    def delete(self, uuid=None):
        if self.uuid and self.path.endswith(self.uuid):
            dpath = self.path
        elif uuid:
            dpath = f"{self.path}/{uuid}"
        else:
            raise ValueError("No uuid provided")

        ret = self.client._invoke_("delete", dpath)
        if ret.status_code != 204:
            raise ValueError(f"Could not delete {uuid} {ret.status_code} {ret.content}")
        return None

    def lookup(self, *args, **kwargs):
        ret = self.client._invoke_("get", f"{self.path}/lookup", *args, **kwargs)
        if ret.status_code == 404:
            log.info(f"Could not find {ret.url}")
            return None
        return ret.json()

    def __getitem__(self, key):
        return self.data[key]

    def __iter__(self):
        return self.data.__iter__()

    def __len__(self):
        return self.data.__len__()

    def __contains__(self, key):
        return self.data.__contains__(key)

    def __getattr__(self, name):
        if name in (
            "service",
            "project",
            "component",
            "vulnerability",
            "bom",
            "tag",
            "property",
            "identity",
        ):
            return DTProxy(self.client, name, self.path)
        raise AttributeError(f"DTProxy has no attribute {name}")


class DependencyTrack:
    """A class to interact with dependency-track
    via the REST API."""

    def __init__(self, baseurl, token, verify=True, paginated=False):
        self.baseurl = baseurl
        self._url = urlparse(baseurl)
        self.token = token
        self.verify = verify
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update(
            {
                "X-Api-Key": token,
            }
        )
        self.paginated_param_payload = (
            {"pageSize": "10000", "pageNumber": "1"} if not paginated else {}
        )

    @property
    def project(self):
        return Project(self, "project")

    @property
    def component(self):
        return DTProxy(self, "component")

    @property
    def bom(self):
        return DTProxy(self, "bom")

    @property
    def search(self):
        return DTProxy(self, "search")

    def _invoke_(
        self,
        method,
        path,
        fields=None,
        qp: dict = None,
        paginated=True,
        ignore_status=tuple(),
        **kwargs,
    ):
        qp = qp or {}
        url = f"{self.baseurl}/{path}"
        if method == "get":
            if paginated:
                qp = dict(qp, **self.paginated_param_payload)
            url += f"?{urlencode(qp, doseq=True)}"
        ret = self.session.request(method, url, **kwargs)

        if ret.status_code >= 400 and ret.status_code not in ignore_status:
            raise ValueError(f"{ret.status_code} {ret.content}")
        return ret

    @staticmethod
    def prepare_sbom(
        sbom: Union[Path, dict],
        project_uuid=None,
        project_name=None,
        project_version=None,
        project_metadata=None,
    ):
        if isinstance(sbom, dict):
            sbom_bytes = json.dumps(sbom).encode()
        elif isinstance(sbom, Path):
            sbom_bytes = sbom.read_bytes()
        sbom_encoded = base64.b64encode(sbom_bytes)
        json_ = {
            "bom": sbom_encoded.decode(),
        }

        if project_uuid:
            json_["project"] = project_uuid
        else:
            json_["projectName"] = project_name
            json_["projectVersion"] = project_version
        return json_


class Project(DTProxy):
    preserve_type = True

    @property
    def component(self):
        component_proxy = DTProxy(self.client, f"component/project/{self.uuid}")
        return component_proxy

    @staticmethod
    def from_sbom(sbom: dict):
        artifact = sbom["metadata"]["component"]
        ret = {
            "name": artifact["name"],
            "version": artifact["version"],
            "purl": artifact["purl"],
            "classifier": artifact["type"].upper(),
        }
        for sbom_prop, project_prop in [
            ("description", "description"),
            ("group", "group"),
        ]:
            if not artifact.get(sbom_prop):
                continue
            ret[project_prop] = artifact[sbom_prop]
        return ret
