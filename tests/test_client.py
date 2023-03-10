import uuid
from pathlib import Path
from time import sleep

import pytest
import yaml

import dependencytrack as dt
from dependencytrack import Project


def test_project_not_found(dt_client):
    MISSING = "c554d5f2-ad9e-4d2b-be66-19a81f4bf3af"
    with pytest.raises(dt.exc.NotFound) as excinfo:
        dt_client.project.get(MISSING)
    assert excinfo.value.status == 404


def test_create_conflict(dt_client, sample_project):
    with pytest.raises(dt.exc.Conflict):
        dt_client.project.create(sample_project)


def test_list_projects(dt_client):
    ret = dt_client.project.list()
    assert len(ret) > 0

    project = ret[0]
    assert dt_client.project.get(project["uuid"])["name"] == project["name"]


def test_list_components_by_project(dt_client):
    uuid = dt_client.project.list()[0]["uuid"]
    project = dt_client.project.get(uuid)

    # The actual API layout is messy since
    #  it mixes the project and component.
    components = project.component.list()
    assert len(components)


def test_create_project(dt_client):
    project = {
        "name": "deleteme",
        "version": f"{uuid.uuid4()}",
    }
    other = {
        "group": "io.github",
        "classifier": "APPLICATION",
        "tags": [{"name": "fake-tag-1"}, {"name": "fake-tag-2"}],
    }
    ret = dt_client.project.create(entry=dict(project, **other))
    assert "uuid" in ret
    dt_client.project.get(ret["uuid"]).delete()
    with pytest.raises(dt.exc.NotFound) as excinfo:
        dt_client.project.get(ret["uuid"])
    assert excinfo.value.instance.endswith(ret["uuid"])


def test_add_component_to_project(dt_client, complex_project):
    sbom_json = Path("tests/sbom.json")

    # Add BOM.
    bom_payload = dt_client.prepare_sbom(
        sbom=sbom_json, project_uuid=complex_project["uuid"]
    )
    dt_client.bom.upload(bom_payload=bom_payload)

    # Wait for BOM to be processed by Dependency-Track.
    sleep(2)
    components = complex_project.component.list(fields=["purl"])
    assert len(components) > 0

    self_component = {
        "name": complex_project["name"],
        "version": complex_project["version"],
        "group": complex_project["group"],
        "purl": complex_project["purl"],
        "classifier": complex_project["classifier"],
    }
    complex_project.component.create(entry=self_component)

    ret = dt_client.component.identity.list(purl=complex_project["purl"])
    assert ret
    project = ret[0]
    assert project["purl"] == complex_project["purl"]


def test_project_property(dt_client, sample_project):
    project = dt_client.project.get(sample_project["uuid"])
    properties = project.property.list()
    assert len(properties) == 2


def test_get_all_components(dt_client, sample_project):
    ret = dt_client.component.identity.list(
        purl="pkg:composer/symfony/var-dumper@5.4.0"
    )
    assert len(ret) > 0


def test_tag(dt_client):
    ret = dt_client.project.tag.get("fake-tag-1")
    assert len(ret) > 0


def test_sbom_put(dt_client, sample_project):
    import base64
    from pathlib import Path

    sbom_json = Path(__file__).parent / "sbom.json"
    sbom = {
        "projectName": sample_project["name"],
        "projectVersion": sample_project["version"] + "-sbom",
        "autoCreate": True,
        "bom": base64.b64encode(sbom_json.read_bytes()).decode(),
    }
    ret = dt_client.bom.upload(sbom)
    assert "token" in ret


def test_project_from_sbom():
    sbom = yaml.safe_load(Path("tests/sbom.json").read_text())
    project = Project.from_sbom(sbom)
    assert project["classifier"] == "APPLICATION"


def test_services(dt_client, complex_project, complex_project_service):
    services = complex_project.service.list()
    assert len(services) > 0
