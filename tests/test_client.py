import uuid
from pathlib import Path
from time import sleep

import yaml

from dependencytrack import Project


def test_project_not_found(dt):
    MISSING = "c554d5f2-ad9e-4d2b-be66-19a81f4bf3af"
    assert dt.project.get(MISSING) is None


def test_list_projects(dt):
    ret = dt.project.list()
    assert len(ret) > 0

    project = ret[0]
    assert dt.project.get(project["uuid"])["name"] == project["name"]


def test_list_components_by_project(dt):
    uuid = dt.project.list()[0]["uuid"]
    project = dt.project.get(uuid)

    # The actual API layout is messy since
    #  it mixes the project and component.
    components = project.component.list()
    assert len(components)


def test_create_project(dt):
    project = {
        "name": "deleteme",
        "version": f"{uuid.uuid4()}",
    }
    other = {
        "group": "io.github",
        "classifier": "APPLICATION",
        "tags": [{"name": "fake-tag-1"}, {"name": "fake-tag-2"}],
    }
    ret = dt.project.create(entry=dict(project, **other))
    assert "uuid" in ret
    dt.project.get(ret["uuid"]).delete()
    assert dt.project.get(ret["uuid"]) is None


def test_add_component_to_project(dt, complex_project):
    sbom_json = Path("tests/sbom.json")

    # Add BOM.
    bom_payload = dt.prepare_sbom(sbom=sbom_json, project_uuid=complex_project["uuid"])
    dt.bom.upload(bom_payload=bom_payload)

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

    ret = dt.component.identity.list(purl=complex_project["purl"])
    assert ret
    project = ret[0]
    assert project["purl"] == complex_project["purl"]


def test_project_property(dt, sample_project):
    project = dt.project.get(sample_project["uuid"])
    properties = project.property.list()
    assert len(properties) == 2


def test_get_all_components(dt, sample_project):
    ret = dt.component.identity.list(purl="pkg:composer/symfony/var-dumper@5.4.0")
    assert len(ret) > 0


def test_tag(dt):
    ret = dt.project.tag.get("fake-tag-1")
    assert len(ret) > 0


def test_sbom_put(dt, sample_project):
    import base64
    from pathlib import Path

    sbom_json = Path(__file__).parent / "sbom.json"
    sbom = {
        "projectName": sample_project["name"],
        "projectVersion": sample_project["version"] + "-sbom",
        "autoCreate": True,
        "bom": base64.b64encode(sbom_json.read_bytes()).decode(),
    }
    ret = dt.bom.upload(sbom)
    assert "token" in ret


def test_project_from_sbom():
    sbom = yaml.safe_load(Path("tests/sbom.json").read_text())
    project = Project.from_sbom(sbom)
    assert project["classifier"] == "APPLICATION"
